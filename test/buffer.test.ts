import { describe, expect, test } from 'vitest';
import { concatBuffers } from '../src/utils/buffer.js';

// This helper is realm-agnostic: it never returns a Node `Buffer`, so every
// value is a plain `Uint8Array` created from the ambient intrinsic. Branching
// on a Node `Buffer` fast path used to break dual-realm runtimes (vitest +
// jsdom), where a `Buffer`-derived value fails `instanceof Uint8Array` inside
// `@noble/curves`. The prototype-identity assertion below pins that guarantee.
describe('buffer utilities', () => {
  test('concatenates buffers', () => {
    const result = concatBuffers(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3]));
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });

  test('concatBuffers returns the ambient Uint8Array (not a Buffer)', () => {
    // The `Buffer` fast path this fork removed would fail this assertion:
    // Node `Buffer` has a different prototype than the ambient `Uint8Array`.
    expect(Object.getPrototypeOf(concatBuffers(new Uint8Array([1]), new Uint8Array([2])))).toBe(Uint8Array.prototype);
  });
});
