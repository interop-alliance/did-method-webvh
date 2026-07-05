/**
 * Default did:webvh history-log verifier.
 *
 * Lives in its own module so the core API ({@link createDID} / {@link updateDID}
 * / {@link resolveDIDFromLog} / {@link deactivateDID}) can default `verifier` to
 * it without depending on the did-io driver. `driver.ts` re-exports it for
 * backward compatibility.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import type { Verifier } from './interfaces.js';

/**
 * Default did:webvh history-log verifier: Ed25519 over `@noble/curves`. The
 * resolver passes the raw 32-byte public key (multicodec header already
 * stripped), so this verifies the signature directly.
 *
 * There is deliberately no catch-all here: `ed25519.verify` returns `false` for
 * a clean signature mismatch and throws only for programming errors (wrong
 * types or lengths, cross-realm `Uint8Array`s). Swallowing those throws once
 * masked a realm bug as a misleading "proof failed verification", so they are
 * left to propagate.
 */
export const defaultWebvhLogVerifier: Verifier = {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return ed25519.verify(signature, message, publicKey);
  },
};
