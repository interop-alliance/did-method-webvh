/**
 * did-io-compatible did:webvh driver for JSON-LD document loaders.
 *
 * `@interop/security-document-loader` (and any did-io `CachedResolver`) expects
 * a DID-method driver shaped `{ method, get({ did, url }) }`. This module
 * provides that shape over {@link resolveDID}, plus inlined `did#fragment`
 * dereferencing, so consumers can resolve `did:webvh` DIDs (and dereference a
 * verification method by fragment) without the core resolver taking on the
 * did-io / digitalbazaar dependency stack. The returned driver is a plain object
 * literal -- this module imports nothing from did-io.
 *
 * History-log proofs are verified with a caller-supplied `verifier`, defaulting
 * to {@link defaultWebvhLogVerifier} (Ed25519 over `@noble/curves`), so the
 * package stays crypto-agnostic for callers who bring their own (an
 * `AbstractCrypto` subclass, an HSM-backed verifier, etc.).
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import type { DIDDoc, Verifier } from './interfaces.js';
import { resolveDID } from './method.js';

/** JSON-LD context for `Multikey` verification methods. */
const MULTIKEY_CONTEXT = 'https://w3id.org/security/multikey/v1';

/**
 * Default did:webvh history-log verifier: Ed25519 over `@noble/curves`. The
 * resolver passes the raw 32-byte public key (multicodec header already
 * stripped), so this verifies the signature directly.
 */
export const defaultWebvhLogVerifier: Verifier = {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  },
};

/**
 * Dereferences a `did#fragment` to its node (verification method or service)
 * within an already-resolved DID document, attaching an appropriate JSON-LD
 * `@context`. Mirrors `@interop/did-web-resolver`'s `getNode` without the
 * dependency.
 *
 * @param doc The resolved DID document.
 * @param id The fully-qualified node id (`did#fragment`).
 * @returns The matched node with an `@context`.
 */
function dereferenceFragment(doc: DIDDoc, id: string): Record<string, unknown> {
  const hasId = (entry: unknown): entry is Record<string, unknown> =>
    typeof entry === 'object' && entry !== null && (entry as { id?: unknown }).id === id;

  let match = (doc.verificationMethod ?? []).find(hasId) as Record<string, unknown> | undefined;
  if (!match) {
    for (const [key, value] of Object.entries(doc)) {
      if (key === '@context' || key === 'verificationMethod') {
        continue;
      }
      if (Array.isArray(value)) {
        match = value.find(hasId);
      } else if (hasId(value)) {
        match = value;
      }
      if (match) {
        break;
      }
    }
  }
  if (!match) {
    throw new Error(`DID document entity with id "${id}" not found.`);
  }

  const context = match.type === 'Multikey' ? MULTIKEY_CONTEXT : doc['@context'];
  return { '@context': context, ...structuredClone(match) };
}

/**
 * Builds a did-io-compatible `did:webvh` driver for a document loader's
 * resolver. A bare DID resolves to its DID document; a `did#fragment` URL is
 * dereferenced straight to its verification-method (or service) node.
 *
 * @param options Driver options.
 * @param [options.verifier] Verifier for the DID's history-log proofs. Defaults
 *   to {@link defaultWebvhLogVerifier}.
 * @returns A `{ method, get }` driver.
 */
export function createDidWebvhDriver({ verifier = defaultWebvhLogVerifier }: { verifier?: Verifier } = {}): {
  method: string;
  get(options: { did?: string; url?: string }): Promise<DIDDoc | Record<string, unknown>>;
} {
  return {
    method: 'webvh',
    async get({ did, url } = {}): Promise<DIDDoc | Record<string, unknown>> {
      const didOrUrl = did ?? url;
      if (!didOrUrl) {
        throw new TypeError('A DID or a URL is required to resolve.');
      }
      // Separate the bare DID from any `?query` or `#fragment`.
      const [didAuthority = ''] = didOrUrl.split(/[#?]/);
      const fragment = didOrUrl.includes('#') ? didOrUrl.slice(didOrUrl.indexOf('#') + 1) : undefined;

      const { doc, meta } = await resolveDID(didAuthority, { verifier });
      if (!doc) {
        throw new Error(meta?.problemDetails?.detail ?? `Could not resolve "${didAuthority}".`);
      }
      if (fragment) {
        return dereferenceFragment(doc, `${doc.id}#${fragment}`);
      }
      return doc;
    },
  };
}
