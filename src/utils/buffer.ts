import { base64 } from '@scure/base';

// These byte helpers are deliberately realm-agnostic: they never touch Node's
// `Buffer`, so every value they return is a plain `Uint8Array` created from the
// ambient intrinsic. Branching on a Node `Buffer` fast path used to break
// dual-realm runtimes (e.g. vitest + jsdom): `Buffer.concat(...)` returns a
// value whose realm's `Uint8Array` differs from the one loaded modules see, so
// downstream `instanceof Uint8Array` checks (inside `@noble/curves`) fail. The
// pure-JS paths below cost microseconds on functions that are nowhere hot;
// correctness in every runtime wins.

// Helper to convert bytes to hex string
const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

// Buffer polyfill for browser environments
export const createBuffer = (input: string, encoding?: BufferEncoding): Uint8Array => {
  // Handle base64 encoding via @scure/base (browser/RN-safe, no Buffer)
  if (encoding === 'base64') {
    return base64.decode(input);
  }

  // Default to UTF-8 encoding
  return new TextEncoder().encode(input);
};

export const bufferToString = (buffer: Uint8Array, encoding?: BufferEncoding): string => {
  // Handle base64 encoding via @scure/base (browser/RN-safe, no Buffer)
  if (encoding === 'base64') {
    return base64.encode(buffer);
  }

  // Handle hex encoding specifically
  if (encoding === 'hex') {
    return bytesToHex(buffer);
  }

  // Default to UTF-8 encoding
  return new TextDecoder().decode(buffer);
};

export const concatBuffers = (...buffers: Uint8Array[]): Uint8Array => {
  // Calculate total length
  const totalLength = buffers.reduce((acc, buf) => acc + buf.length, 0);

  // Create new array and copy all buffers into it
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const buffer of buffers) {
    result.set(buffer, offset);
    offset += buffer.length;
  }

  return result;
};
