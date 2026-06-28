import { base64 } from '@scure/base';

// Node and Bun expose a global `Buffer`; browsers, React Native, and Web/Service
// Workers do not. Testing for the global directly (rather than sniffing for
// `window`) routes every non-Node runtime -- including workers, which have
// neither `window` nor `process` -- to the pure-JS / @scure/base path.
const hasNodeBuffer = typeof Buffer !== 'undefined';

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

  if (hasNodeBuffer) {
    return Buffer.from(input, encoding);
  }

  // Default to UTF-8 encoding
  return new TextEncoder().encode(input);
};

export const bufferToString = (buffer: Uint8Array, encoding?: BufferEncoding): string => {
  // Handle base64 encoding via @scure/base (browser/RN-safe, no Buffer)
  if (encoding === 'base64') {
    return base64.encode(buffer);
  }

  if (hasNodeBuffer) {
    return Buffer.from(buffer).toString(encoding);
  }

  // Handle hex encoding specifically
  if (encoding === 'hex') {
    return bytesToHex(buffer);
  }

  // Default to UTF-8 encoding
  return new TextDecoder().decode(buffer);
};

export const concatBuffers = (...buffers: Uint8Array[]): Uint8Array => {
  if (hasNodeBuffer) {
    return Buffer.concat(buffers);
  }

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
