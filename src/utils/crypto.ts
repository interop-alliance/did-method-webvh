/// <reference lib="dom" />
import { sha256 } from '@noble/hashes/sha2.js';
import { canonicalizeStrict } from './canonicalize.js';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm } from './multiformats.js';

const encoder = new TextEncoder();

function arrayBufferToHex(buffer: ArrayBufferLike | Uint8Array): string {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function createHash(data: string): Promise<Uint8Array> {
  return sha256(encoder.encode(data));
}

export async function createHashHex(data: string): Promise<string> {
  const hash = await createHash(data);
  const view = new Uint8Array(hash.buffer);
  return arrayBufferToHex(view);
}

export const createSCID = async (logEntryHash: string): Promise<string> => {
  return logEntryHash;
};

// Cache for deriveHash operations to avoid redundant computation. Bounded with
// a simple FIFO eviction so a long-lived process (e.g. a resolver serving many
// DIDs, keyed by full log entries) cannot grow it without limit.
export const HASH_CACHE_MAX_ENTRIES = 500;
const hashCache = new Map<string, string>();

/** @internal Test-only accessor for the bounded deriveHash memo cache size. */
export const getHashCacheSizeForTests = (): number => hashCache.size;

function getCachedHash(input: unknown): string | undefined {
  try {
    const key = JSON.stringify(input);
    return hashCache.get(key);
  } catch {
    return undefined;
  }
}

function setCachedHash(input: unknown, hash: string): void {
  try {
    const key = JSON.stringify(input);
    hashCache.set(key, hash);
    // Map preserves insertion order, so the first key is the oldest insertion.
    if (hashCache.size > HASH_CACHE_MAX_ENTRIES) {
      const oldestKey = hashCache.keys().next().value;
      if (oldestKey !== undefined) {
        hashCache.delete(oldestKey);
      }
    }
  } catch {
    // Ignore caching errors
  }
}

// Input must be strict JSON-compatible and must not contain explicit undefined values.
export async function deriveHash(input: unknown): Promise<string> {
  const cached = getCachedHash(input);
  if (cached) {
    return cached;
  }
  const data = canonicalizeStrict(input);
  const hash = await createHash(data);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  const result = encodeBase58Btc(multihash);
  setCachedHash(input, result);
  return result;
}

/**
 * Derives a `nextKeyHashes` entry from an update key (its `did:key`
 * multibase). Returns the spec's bare base58btc multihash, NOT `z`-prefixed
 * multibase -- did:webvh 1.0 mandates `nextKeyHashes` entries be multihash
 * base58btc. Do NOT multibase-encode the result; the asymmetry with every
 * other `z`-prefixed value in this API is intentional and spec-required.
 */
export const deriveNextKeyHash = async (input: string): Promise<string> => {
  const hash = await createHash(input);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  return encodeBase58Btc(multihash);
};
