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

import type { IDIDResolutionResult } from '@interop/data-integrity-core';
import { parseVerificationMethodUrl } from './dereference.js';
import { narrowDriverOptions, requireFragmentNode, requireResolvedDocument } from './driver-shared.js';
import type { DIDDoc, FetchLike, Verifier } from './interfaces.js';
import { resolveDID } from './method.js';
import { defaultWebvhLogVerifier } from './verifier.js';

/**
 * Default did:webvh history-log verifier, re-exported from {@link ./verifier}
 * for backward compatibility (its canonical home moved so the core API can
 * default `verifier` to it without importing this did-io driver module).
 */
export { defaultWebvhLogVerifier };

/**
 * Builds a did-io-compatible `did:webvh` driver for a document loader's
 * resolver. A bare DID resolves to its DID document; a `did#fragment` URL is
 * dereferenced straight to its verification-method (or service) node. A
 * `did?versionId=<id>#fragment` URL dereferences the node in the document at
 * that version, found by the document's own id, so a portable DID's earlier
 * versions are reachable under the current DID.
 *
 * Resolution failures in `get()` throw a `DIDResolutionError` (from
 * `@interop/data-integrity-core`) carrying the resolution error `code` and RFC
 * 9457 `problemDetails`, so callers can branch on the failure class instead of
 * string-matching messages. A fragment that names no node in the resolved
 * document throws a `VerificationMethodError` (same package) with code
 * `notFound` and the requested DID URL in `verificationMethod`. The driver
 * also implements the optional `resolveDID()` of did-io's `DidMethodDriver`: a
 * non-throwing, spec-shaped resolution returning the DID Resolution Result
 * envelope produced natively by this package's {@link resolveDID} (preserving
 * webvh document metadata such as `scid` and `updateKeys`).
 *
 * @param options Driver options.
 * @param [options.verifier] Verifier for the DID's history-log proofs. Defaults
 *   to {@link defaultWebvhLogVerifier}.
 * @param [options.fetch] Fetch override for retrieving the DID log and
 *   `did-witness.json`. Defaults to the global `fetch`. A did-io caller can
 *   override it per resolution via `resolveDID({ did, fetch })`.
 * @returns A `{ method, get, resolveDID }` driver.
 */
export function createDidWebvhDriver({
  verifier = defaultWebvhLogVerifier,
  fetch: fetchFn,
}: {
  verifier?: Verifier;
  fetch?: FetchLike;
} = {}): {
  method: string;
  get(options: { did?: string; url?: string }): Promise<DIDDoc | Record<string, unknown>>;
  resolveDID(options: { did: string; [key: string]: unknown }): Promise<IDIDResolutionResult>;
} {
  return {
    method: 'webvh',
    async get({ did, url } = {}): Promise<DIDDoc | Record<string, unknown>> {
      const didOrUrl = did ?? url;
      if (!didOrUrl) {
        throw new TypeError('A DID or a URL is required to resolve.');
      }
      // Any DID parameter other than `versionId` is rejected by the parser.
      const { did: didAuthority, versionId, fragment } = parseVerificationMethodUrl(didOrUrl);

      const result = await resolveDID(didAuthority, { verifier, fetch: fetchFn, versionId });
      const doc = requireResolvedDocument(result, didAuthority);
      return fragment ? requireFragmentNode(doc, fragment, didOrUrl) : doc;
    },
    async resolveDID({ did, ...options }: { did: string; [key: string]: unknown }): Promise<IDIDResolutionResult> {
      const { error, fetch: perCallFetch, selectors } = narrowDriverOptions(options);
      if (error) {
        return error;
      }
      return resolveDID(did, { verifier, fetch: perCallFetch ?? fetchFn, ...selectors });
    },
  };
}
