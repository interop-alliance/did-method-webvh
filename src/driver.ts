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
import { DIDResolutionError } from '@interop/data-integrity-core';
import type { DIDDoc, Verifier } from './interfaces.js';
import { resolveDID } from './method.js';
import { defaultWebvhLogVerifier } from './verifier.js';

/**
 * Default did:webvh history-log verifier, re-exported from {@link ./verifier}
 * for backward compatibility (its canonical home moved so the core API can
 * default `verifier` to it without importing this did-io driver module).
 */
export { defaultWebvhLogVerifier };

/** JSON-LD context for `Multikey` verification methods. */
const MULTIKEY_CONTEXT = 'https://w3id.org/security/multikey/v1';

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
 * Resolution failures in `get()` throw a `DIDResolutionError` (from
 * `@interop/data-integrity-core`) carrying the resolution error `code` and RFC
 * 9457 `problemDetails`, so callers can branch on the failure class instead of
 * string-matching messages. The driver also implements the optional
 * `resolveDID()` of did-io's `DidMethodDriver`: a non-throwing, spec-shaped
 * resolution returning the DID Resolution Result envelope produced natively by
 * this package's {@link resolveDID} (preserving webvh document metadata such
 * as `scid` and `updateKeys`).
 *
 * @param options Driver options.
 * @param [options.verifier] Verifier for the DID's history-log proofs. Defaults
 *   to {@link defaultWebvhLogVerifier}.
 * @returns A `{ method, get, resolveDID }` driver.
 */
export function createDidWebvhDriver({ verifier = defaultWebvhLogVerifier }: { verifier?: Verifier } = {}): {
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
      // Separate the bare DID from any `?query` or `#fragment`.
      const [didAuthority = ''] = didOrUrl.split(/[#?]/);
      const fragment = didOrUrl.includes('#') ? didOrUrl.slice(didOrUrl.indexOf('#') + 1) : undefined;

      const { didDocument, didResolutionMetadata } = await resolveDID(didAuthority, { verifier });
      // The envelope's IDIDDocument is structurally stricter than this
      // package's DIDDoc; narrow back at this single boundary.
      const doc = didDocument as unknown as DIDDoc | null;
      if (!doc) {
        const { error, problemDetails } = didResolutionMetadata;
        const detail = problemDetails?.detail ?? `Could not resolve "${didAuthority}".`;
        throw new DIDResolutionError(detail, {
          code: error ?? 'internalError',
          problemDetails,
        });
      }
      if (fragment) {
        return dereferenceFragment(doc, `${doc.id}#${fragment}`);
      }
      return doc;
    },
    async resolveDID({ did, ...options }: { did: string; [key: string]: unknown }): Promise<IDIDResolutionResult> {
      // The did-io driver contract passes resolution options untyped
      // (spec-extensible); narrow the version selectors this method supports.
      const { versionId, versionNumber, versionTime } = options as {
        versionId?: string;
        versionNumber?: number;
        versionTime?: Date | string;
      };
      return resolveDID(did, {
        verifier,
        versionId,
        versionNumber,
        versionTime: typeof versionTime === 'string' ? new Date(versionTime) : versionTime,
      });
    },
  };
}
