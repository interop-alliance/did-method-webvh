/**
 * Helpers shared by the did:webvh and did:vh did-io drivers: `did#fragment`
 * dereferencing within a resolved DID document, the conversion of a result
 * envelope into a thrown error, and the narrowing of did-io's untyped
 * resolution options.
 */
import { DIDResolutionError, type IDIDResolutionResult, VerificationMethodError } from '@interop/data-integrity-core';
import { hasMatchingId } from './did-document.js';
import type { DIDDoc, FetchLike } from './interfaces.js';
import { toErrorResult } from './resolver-result.js';

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
 * @returns The matched node with an `@context`, or `undefined` if no node has
 *   that id.
 */
function dereferenceFragment(doc: DIDDoc, id: string): Record<string, unknown> | undefined {
  const hasId = hasMatchingId(id);

  let match = (doc.verificationMethod ?? []).find(hasId) as Record<string, unknown> | undefined;
  if (!match) {
    for (const [key, value] of Object.entries(doc)) {
      if (key === '@context' || key === 'verificationMethod') {
        continue;
      }
      if (Array.isArray(value)) {
        match = value.find(hasId) as Record<string, unknown> | undefined;
      } else if (hasId(value)) {
        match = value as unknown as Record<string, unknown>;
      }
      if (match) {
        break;
      }
    }
  }
  if (!match) {
    return undefined;
  }

  const context = match.type === 'Multikey' ? MULTIKEY_CONTEXT : doc['@context'];
  return { '@context': context, ...structuredClone(match) };
}

/**
 * Returns the document of a resolution result, for a driver's `get()`. Throws
 * a `DIDResolutionError` carrying the result's error code and
 * `problemDetails` when the result has an error or no document.
 *
 * Any resolution error is a failure here, even when the envelope also
 * carries a document (the resolver preserves a historical snapshot next to a
 * witness failure when an explicit version selector is given). A loader
 * consumer asking for the document must not receive one whose resolution the
 * resolver flagged as invalid.
 *
 * @param result The resolution result envelope.
 * @param subject The DID or DID URL that was resolved, for the error message.
 * @returns The resolved DID document.
 */
export function requireResolvedDocument(result: IDIDResolutionResult, subject: string): DIDDoc {
  const { didDocument, didResolutionMetadata } = result;
  // The envelope's IDIDDocument is structurally stricter than this
  // package's DIDDoc; narrow back at this single boundary.
  const doc = didDocument as unknown as DIDDoc | null;
  if (!doc || didResolutionMetadata.error) {
    const { error, problemDetails } = didResolutionMetadata;
    throw new DIDResolutionError(problemDetails?.detail ?? `Could not resolve "${subject}".`, {
      code: error ?? 'internalError',
      problemDetails,
    });
  }
  return doc;
}

/**
 * Returns the node a fragment names in a resolved document, for a driver's
 * `get()`. The node is looked up by the document's own id, so a portable
 * DID's earlier versions resolve under the current DID. An absent node has no
 * kind, so a missing service is reported the same way as a missing
 * verification method: a `VerificationMethodError` with code `notFound`.
 *
 * @param doc The resolved DID document.
 * @param fragment The fragment, without the `#`.
 * @param didUrl The requested DID URL, reported in `verificationMethod`.
 * @returns The matched node with an `@context`.
 */
export function requireFragmentNode(doc: DIDDoc, fragment: string, didUrl: string): Record<string, unknown> {
  const id = `${doc.id}#${fragment}`;
  const node = dereferenceFragment(doc, id);
  if (!node) {
    throw new VerificationMethodError(`DID document entity with id "${id}" not found.`, {
      code: 'notFound',
      verificationMethod: didUrl,
    });
  }
  return node;
}

/**
 * Narrows the options of a driver's `resolveDID()`. The did-io driver
 * contract passes resolution options untyped (spec-extensible), so this
 * reads the version selectors and the per-resolution fetch override. A
 * `versionTime` string becomes a `Date`.
 *
 * @param options The untyped resolution options.
 * @returns The selectors and the fetch override, or `error` holding the
 *   result to return when an option is invalid.
 */
export function narrowDriverOptions(options: Record<string, unknown>): {
  error?: IDIDResolutionResult;
  fetch?: FetchLike;
  selectors: { versionId?: string; versionNumber?: number; versionTime?: Date };
} {
  const { versionId, versionNumber, versionTime, fetch } = options as {
    versionId?: string;
    versionNumber?: number;
    versionTime?: Date | string;
    fetch?: unknown;
  };
  if (fetch !== undefined && typeof fetch !== 'function') {
    return { error: toErrorResult('invalidOptions', 'Invalid fetch option: expected function.'), selectors: {} };
  }
  return {
    fetch: fetch as FetchLike | undefined,
    selectors: {
      versionId,
      versionNumber,
      versionTime: typeof versionTime === 'string' ? new Date(versionTime) : versionTime,
    },
  };
}
