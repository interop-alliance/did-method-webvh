// This helper is deliberately realm-agnostic: it never touches Node's
// `Buffer`, so every value it returns is a plain `Uint8Array` created from the
// ambient intrinsic. Branching on a Node `Buffer` fast path used to break
// dual-realm runtimes (e.g. vitest + jsdom): `Buffer.concat(...)` returns a
// value whose realm's `Uint8Array` differs from the one loaded modules see, so
// downstream `instanceof Uint8Array` checks (inside `@noble/curves`) fail. The
// pure-JS path below costs microseconds on a function that is nowhere hot;
// correctness in every runtime wins.

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
