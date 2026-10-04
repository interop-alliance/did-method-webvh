/// <reference lib="dom" />
import { sha256 } from '@noble/hashes/sha2.js';
import { canonicalizeStrict } from './canonicalize.js';
import { normalizeEd25519Multikey } from './did-key.js';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm } from './multiformats.js';

const encoder = new TextEncoder();

export async function createHash(data: string): Promise<Uint8Array> {
  return sha256(encoder.encode(data));
}

const toBase58Multihash = (hash: Uint8Array): string =>
  encodeBase58Btc(createMultihash(hash, MultihashAlgorithm.SHA2_256));

// Cache for deriveHash operations to avoid redundant computation. Bounded with
// a simple FIFO eviction so a long-lived process (e.g. a resolver serving many
// DIDs, keyed by full log entries) cannot grow it without limit.
export const HASH_CACHE_MAX_ENTRIES = 500;
const hashCache = new Map<string, string>();

/** @internal Test-only accessor for the bounded deriveHash memo cache size. */
export const getHashCacheSizeForTests = (): number => hashCache.size;

function cacheKeyFor(input: unknown): string | undefined {
  try {
    return JSON.stringify(input);
  } catch {
    return undefined;
  }
}

function setCachedHash(key: string, hash: string): void {
  hashCache.set(key, hash);
  // Map preserves insertion order, so the first key is the oldest insertion.
  if (hashCache.size > HASH_CACHE_MAX_ENTRIES) {
    const oldestKey = hashCache.keys().next().value;
    if (oldestKey !== undefined) {
      hashCache.delete(oldestKey);
    }
  }
}

// Input must be strict JSON-compatible and must not contain explicit undefined values.
export async function deriveHash(input: unknown): Promise<string> {
  const key = cacheKeyFor(input);
  if (key !== undefined) {
    const cached = hashCache.get(key);
    if (cached) {
      return cached;
    }
  }
  const data = canonicalizeStrict(input);
  const result = toBase58Multihash(await createHash(data));
  if (key !== undefined) {
    setCachedHash(key, result);
  }
  return result;
}

/**
 * Derives a `nextKeyHashes` entry from an update key. Accepts a bare Ed25519
 * multikey, a `did:key:` DID, or a `did:key:` verification method id; all
 * three hash the bare multikey, so they yield the same entry. Throws when the
 * input is not a 32-byte Ed25519 multikey. Returns the spec's bare base58btc
 * multihash, NOT `z`-prefixed multibase -- did:webvh 1.0 mandates
 * `nextKeyHashes` entries be multihash base58btc. Do NOT multibase-encode the
 * result; the asymmetry with every other `z`-prefixed value in this API is
 * intentional and spec-required.
 */
export const deriveNextKeyHash = async (input: string): Promise<string> => {
  let keyMultibase: string;
  try {
    keyMultibase = normalizeEd25519Multikey(input);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid next key: ${message}`);
  }
  return toBase58Multihash(await createHash(keyMultibase));
};
