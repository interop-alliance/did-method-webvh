import { describe, expect, test } from 'vitest';
import { bufferToString, concatBuffers, createBuffer } from '../src/utils/buffer.js';

// These helpers are realm-agnostic: they never return a Node `Buffer`, so every
// value is a plain `Uint8Array` created from the ambient intrinsic. Branching on
// a Node `Buffer` fast path used to break dual-realm runtimes (vitest + jsdom),
// where a `Buffer`-derived value fails `instanceof Uint8Array` inside
// `@noble/curves`. The prototype-identity assertions below pin that guarantee.
describe('buffer utilities', () => {
  test('round-trips utf-8 text', () => {
    const bytes = createBuffer('hello did:webvh');
    expect(bufferToString(bytes)).toBe('hello did:webvh');
  });

  test('decodes and encodes base64', () => {
    const bytes = createBuffer('aGVsbG8=', 'base64');
    expect(bufferToString(bytes)).toBe('hello');
    expect(bufferToString(bytes, 'base64')).toBe('aGVsbG8=');
  });

  test('encodes hex', () => {
    expect(bufferToString(new Uint8Array([0, 1, 171, 255]), 'hex')).toBe('0001abff');
  });

  test('concatenates buffers', () => {
    const result = concatBuffers(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3]));
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });

  test('createBuffer / concatBuffers return the ambient Uint8Array (not a Buffer)', () => {
    // The `Buffer` fast paths this fork removed would fail these assertions:
    // Node `Buffer` has a different prototype than the ambient `Uint8Array`.
    expect(Object.getPrototypeOf(createBuffer('abc'))).toBe(Uint8Array.prototype);
    expect(Object.getPrototypeOf(createBuffer('aGVsbG8=', 'base64'))).toBe(Uint8Array.prototype);
    expect(Object.getPrototypeOf(concatBuffers(new Uint8Array([1]), new Uint8Array([2])))).toBe(Uint8Array.prototype);
  });
});
