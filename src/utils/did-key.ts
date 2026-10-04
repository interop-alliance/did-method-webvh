/**
 * `did:key` parsing and Ed25519 key normalization.
 *
 * Leaf module (imports only `multiformats.ts`) so `utils.ts` and
 * `utils/crypto.ts` can share one parser without import cycles.
 */
import type { ParsedDidKeyVerificationMethod } from '../interfaces.js';
import { decodeEd25519Multikey, multibaseDecode } from './multiformats.js';

const DID_KEY_PREFIX = 'did:key:';

function validateDidKeyMultibase(keyMultibase: string): void {
  if (!keyMultibase) {
    throw new Error('Malformed did:key identifier');
  }

  try {
    multibaseDecode(keyMultibase);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Malformed did:key identifier: ${message}`);
  }
}

export function parseDidKeyDid(input: string): { did: string; keyMultibase: string } {
  if (typeof input !== 'string') {
    throw new Error('did:key DID must be a string');
  }

  const match = input.match(/^did:key:([^#/?]+)$/);
  if (!match) {
    throw new Error('Malformed did:key DID');
  }

  const keyMultibase = match[1];
  validateDidKeyMultibase(keyMultibase);

  return {
    did: `${DID_KEY_PREFIX}${keyMultibase}`,
    keyMultibase,
  };
}

export function parseDidKeyVerificationMethod(input: string): ParsedDidKeyVerificationMethod {
  if (typeof input !== 'string') {
    throw new Error('did:key verificationMethod must be a string');
  }

  if (input.startsWith('#')) {
    throw new Error('did:key verificationMethod must be an absolute DID URL');
  }

  const match = input.match(/^did:key:([^#/?]+)(?:#([^#/?]+))?$/);
  if (!match) {
    throw new Error('Malformed did:key verificationMethod');
  }

  const parsedDid = parseDidKeyDid(`${DID_KEY_PREFIX}${match[1]}`);
  const fragment = match[2];

  // If fragment is present, it MUST equal the body multibase exactly
  if (fragment && fragment !== parsedDid.keyMultibase) {
    throw new Error(
      `did:key verificationMethod fragment must equal body multibase. ` +
        `Expected fragment '${parsedDid.keyMultibase}' but got '${fragment}'`
    );
  }

  return {
    did: parsedDid.did,
    fragment,
    keyMultibase: parsedDid.keyMultibase,
  };
}

/**
 * Normalizes one caller-supplied Ed25519 key to its bare multikey.
 *
 * Accepts a bare Ed25519 multikey, a `did:key:` DID, or a `did:key:`
 * verification method id. Throws when the input is malformed or is not a
 * 32-byte Ed25519 public key (multicodec header 0xed01).
 *
 * @param key {string} Caller-supplied key.
 * @returns {string} The key as a bare multibase multikey.
 */
export function normalizeEd25519Multikey(key: string): string {
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }
  const { keyMultibase } = key.startsWith(DID_KEY_PREFIX)
    ? parseDidKeyVerificationMethod(key)
    : parseDidKeyDid(`${DID_KEY_PREFIX}${key}`);
  decodeEd25519Multikey(keyMultibase);
  return keyMultibase;
}
