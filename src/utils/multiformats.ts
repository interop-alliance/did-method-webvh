/**
 * multiformats.ts
 *
 * This file provides utilities for working with Multibase and Multikey formats
 * as specified in the DID:WebVH method specification, and re-exports the shared
 * Multihash codec from `@interop/data-integrity-core`.
 */

import {
  createMultihash,
  decodeMultihash,
  decodeMultikey,
  MultihashAlgorithm,
  MultikeyCodec,
} from '@interop/data-integrity-core/multihash';
import { base58, base64urlnopad } from '@scure/base';

// ===== MULTIBASE IMPLEMENTATION =====

/**
 * Supported Multibase encoding types
 */
export enum MultibaseEncoding {
  BASE64URL_NO_PAD = 'u',
  BASE58_BTC = 'z',
}

/**
 * Encodes binary data using Base64URL (no padding)
 * @param bytes - The binary data to encode
 * @returns The base64url encoded string (without the multibase prefix)
 */
export function encodeBase64Url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

/**
 * Decodes a Base64URL (no padding) string to binary data
 * @param str - The base64url encoded string
 * @returns The decoded binary data
 */
function decodeBase64Url(str: string): Uint8Array {
  return base64urlnopad.decode(str);
}

/**
 * Encodes binary data using Base58BTC
 * @param bytes - The binary data to encode
 * @returns The base58btc encoded string (without the multibase prefix)
 */
export function encodeBase58Btc(bytes: Uint8Array): string {
  return base58.encode(bytes);
}

/**
 * Decodes a Base58BTC string to binary data
 * @param str - The base58btc encoded string
 * @returns The decoded binary data
 */
export function decodeBase58Btc(str: string): Uint8Array {
  return base58.decode(str);
}

/**
 * Encodes binary data using the specified multibase encoding
 * @param bytes - The binary data to encode
 * @param encoding - The multibase encoding to use
 * @returns The multibase encoded string (including the prefix)
 */
export function multibaseEncode(
  bytes: Uint8Array,
  encoding: MultibaseEncoding = MultibaseEncoding.BASE64URL_NO_PAD
): string {
  let encoded: string;

  switch (encoding) {
    case MultibaseEncoding.BASE64URL_NO_PAD:
      encoded = encodeBase64Url(bytes);
      break;
    case MultibaseEncoding.BASE58_BTC:
      encoded = encodeBase58Btc(bytes);
      break;
    default:
      throw new Error(`Unsupported multibase encoding: ${encoding}`);
  }

  return `${encoding}${encoded}`;
}

/**
 * Decodes a multibase encoded string to binary data
 * @param str - The multibase encoded string
 * @returns The decoded binary data and the encoding used
 */
export function multibaseDecode(str: string): { bytes: Uint8Array; encoding: MultibaseEncoding } {
  if (!str || str.length < 2) {
    throw new Error('Invalid multibase string: too short');
  }
  const prefix = str[0] as MultibaseEncoding;
  const encoded = str.slice(1);

  let bytes: Uint8Array;

  switch (prefix) {
    case MultibaseEncoding.BASE64URL_NO_PAD:
      bytes = decodeBase64Url(encoded);
      break;
    case MultibaseEncoding.BASE58_BTC:
      bytes = decodeBase58Btc(encoded);
      break;
    default:
      throw new Error(`Unsupported multibase encoding prefix: ${prefix}`);
  }

  return { bytes, encoding: prefix };
}

// ===== MULTIHASH IMPLEMENTATION =====

// The multihash byte codec and the sibling multikey decoder live in
// `@interop/data-integrity-core/multihash`; they are re-exported here so
// consumers of this module keep one import site for the multiformats halves.
export { createMultihash, decodeMultihash, decodeMultikey, MultihashAlgorithm, MultikeyCodec };

/**
 * Decodes a multibase encoded multihash
 * @param str - The multibase encoded multihash
 * @returns The decoded multihash components and the encoding used
 */
export function decodeMultihashFromMultibase(str: string): {
  algorithm: MultihashAlgorithm;
  digestLength: number;
  digest: Uint8Array;
  encoding: MultibaseEncoding;
} {
  const { bytes, encoding } = multibaseDecode(str);
  const multihash = decodeMultihash(bytes);

  return {
    ...multihash,
    encoding,
  };
}

/**
 * Decodes an Ed25519 multikey multibase string to the raw 32-byte public key,
 * validating the base58btc multibase prefix, the `0xed` multicodec, and the
 * key length.
 */
export function decodeEd25519Multikey(publicKeyMultibase: string): Uint8Array {
  return decodeMultikey({
    multikey: publicKeyMultibase,
    expectedCodec: MultikeyCodec.ED25519_PUB,
  }).keyBytes;
}
