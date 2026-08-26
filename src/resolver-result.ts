/**
 * Resolution error classification and spec resolution-result mapping.
 *
 * The error vocabulary (codes, RFC 9457 problem details) is the shared one
 * from `@interop/data-integrity-core`; this module adds the did:webvh-specific
 * classification of thrown errors into codes, the version-selector option
 * validation, and the mapping from this package's `{ did, doc, meta }` core
 * result shape to the DID Resolution spec's result envelope
 * (`IDIDResolutionResult`).
 */
import type { IDIDDocument, IDIDDocumentMetadata, IDIDResolutionResult } from '@interop/data-integrity-core';
import type { DIDDoc, DIDResolutionMeta, DidResolutionError, ProblemDetails } from './interfaces.js';

/** `problemDetails.type` URIs from the did:webvh resolution-error registry. */
export const WEBVH_ERROR_TYPES = {
  conflictingResolutionOptions: 'https://didwebvh.info/latest/resolution-errors/#conflicting-resolution-options',
  versionIdFormatInvalid: 'https://didwebvh.info/latest/resolution-errors/#versionid-format-invalid',
  versionTimeFormatInvalid: 'https://didwebvh.info/latest/resolution-errors/#versiontime-format-invalid',
} as const;

/** Document metadata for a did:webvh resolution result: the standard fields plus this method's extensions. */
export interface WebvhDocumentMetadata extends IDIDDocumentMetadata {
  versionTime?: string;
  scid?: string;
  /** Cache lifetime in seconds; the spec default (3600) when the log never sets `ttl`. */
  ttl?: number;
  updateKeys?: string[];
  nextKeyHashes?: string[];
  prerotation?: boolean;
  portable?: boolean;
  witness?: DIDResolutionMeta['witness'];
  watchers?: string[] | null;
}

const CONTENT_TYPE = 'application/did+ld+json';

/** A structured, non-throwing validation failure for resolution options. */
export interface ResolutionOptionsError {
  code: DidResolutionError;
  detail: string;
  /** did:webvh registry URI for `problemDetails.type`; falls back to the code's default. */
  problemType?: string;
}

export function validateSingleVersionSelector(options: {
  versionId?: string;
  versionTime?: Date;
  versionNumber?: number;
}): ResolutionOptionsError | null {
  const count = [options.versionId, options.versionTime, options.versionNumber].filter(
    (selector) => selector !== undefined
  ).length;
  if (count > 1) {
    return {
      code: 'invalidOptions',
      detail: 'At most one of versionId, versionTime, versionNumber may be supplied; they are mutually exclusive.',
      problemType: WEBVH_ERROR_TYPES.conflictingResolutionOptions,
    };
  }
  return null;
}

/**
 * Validates every resolution-selector combination in one place: at most one
 * version selector, and `verificationMethod` not combined with an exact
 * version selector. (`verificationMethod` + `versionTime` stays allowed -- a
 * supported combined selector: "the document containing this method around
 * this time".) The single entry into `resolveV1Log` calls this, so the
 * in-memory and HTTPS paths reject conflicting selectors identically.
 */
export function validateResolutionSelectors(options: {
  versionId?: string;
  versionTime?: Date;
  versionNumber?: number;
  verificationMethod?: string;
}): ResolutionOptionsError | null {
  const single = validateSingleVersionSelector(options);
  if (single) {
    return single;
  }
  if (options.verificationMethod && (options.versionId !== undefined || options.versionNumber !== undefined)) {
    return {
      code: 'invalidOptions',
      detail: 'Cannot specify both verificationMethod and version number/id',
      problemType: WEBVH_ERROR_TYPES.conflictingResolutionOptions,
    };
  }
  return null;
}

export function mapErrorToCode(error: unknown): DidResolutionError {
  const message = error instanceof Error ? error.message : String(error);
  // Only a genuine failure to fetch the DID log (or a DID-URL resource) is
  // `notFound`. Match the library's own absence messages rather than scanning
  // for "404"/"not found" anywhere in the text: validation errors can embed
  // attacker-controlled log data (e.g. a tampered versionId of "404", or
  // "Invalid update key ... Not found in nextKeyHashes ..."), and those are
  // invalid documents, not missing ones.
  if (/HTTP error! status: 404\b/.test(message) || /DID log not found/i.test(message)) {
    return 'notFound';
  }
  // Any non-404 HTTP error status (4xx/5xx) or network/transport failure is a
  // resolver-side internal error, not an invalid document: a valid DID served
  // from an unauthorized, gone, rate-limited, or failing endpoint must not be
  // reported as a document-validation failure. (404 is handled above as
  // notFound.) Everything else that reaches here is a validation failure.
  if (
    /HTTP error! status: [45]\d\d\b/.test(message) ||
    /fetch failed/i.test(message) ||
    /\b(ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN)\b/.test(message) ||
    /network (error|request failed)/i.test(message)
  ) {
    return 'internalError';
  }
  return 'invalidDid';
}

/** RFC9457-style `type`/`title` for each standard error code. */
const PROBLEM_DETAILS_BY_CODE: Record<DidResolutionError, { type: string; title: string }> = {
  notFound: {
    type: 'https://w3id.org/security#NOT_FOUND',
    title: 'The DID Log or resource was not found.',
  },
  invalidDid: {
    type: 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
    title: 'The resolved DID is invalid.',
  },
  invalidDidUrl: {
    type: 'https://www.w3.org/ns/did#INVALID_DID_URL',
    title: 'The DID URL is invalid.',
  },
  invalidOptions: {
    type: 'https://www.w3.org/ns/did#INVALID_OPTIONS',
    title: 'The DID resolution options are invalid.',
  },
  internalError: {
    type: 'https://www.w3.org/ns/did#INTERNAL_ERROR',
    title: 'An unexpected error occurred during resolution.',
  },
};

/**
 * Builds the `error` + `problemDetails` portion of this package's core result
 * `meta` for a resolution failure.
 *
 * @param code Resolution error code.
 * @param detail Occurrence-specific detail message.
 * @param problemType Optional registry URI overriding the code's default `problemDetails.type`.
 * @param title Optional title overriding the code's default `problemDetails.title`.
 * @returns The error fields for a core result's `meta`.
 */
export function toErrorMeta(
  code: DidResolutionError,
  detail: string,
  problemType?: string,
  title?: string
): { error: DidResolutionError; problemDetails: ProblemDetails } {
  const { type, title: defaultTitle } = PROBLEM_DETAILS_BY_CODE[code];
  return {
    error: code,
    problemDetails: { type: problemType ?? type, title: title ?? defaultTitle, detail },
  };
}

/**
 * Renders a resolution failure directly as a DID Resolution spec result
 * envelope.
 *
 * @param code Resolution error code.
 * @param detail Occurrence-specific detail message.
 * @param problemType Optional registry URI overriding the code's default `problemDetails.type`.
 * @returns A resolution result with `didDocument: null` and the failure on `didResolutionMetadata`.
 */
export function toErrorResult(code: DidResolutionError, detail: string, problemType?: string): IDIDResolutionResult {
  const { error, problemDetails } = toErrorMeta(code, detail, problemType);
  return {
    didResolutionMetadata: { error, problemDetails, message: detail },
    didDocument: null,
    didDocumentMetadata: {},
  };
}

/**
 * Maps this package's core resolution result (`{ did, doc, meta }`, with a
 * flat `meta` mixing document metadata and error state) to the DID Resolution
 * spec's result envelope: document metadata and resolution-process metadata
 * split into their own buckets.
 *
 * @param core The core resolution result. Failure-path results carry only the
 *   `error`/`problemDetails` portion of `meta`, hence the `Partial`.
 * @returns The spec resolution result envelope.
 */
export function toResolutionResult(core: {
  did: string;
  doc: DIDDoc | null;
  meta: Partial<DIDResolutionMeta>;
}): IDIDResolutionResult {
  const { meta } = core;
  // Split meta into the standard documentMetadata + the resolutionMetadata extras.
  const { error, problemDetails, ...documentMeta } = meta;
  const didDocumentMetadata: WebvhDocumentMetadata = { ...documentMeta };
  // This package's DIDDoc is structurally looser than IDIDDocument (optional
  // `id`, free-form `@context`), hence the cast at this single boundary.
  const didDocument = (core.doc as unknown as IDIDDocument) ?? null;

  if (error) {
    const didResolutionMetadata: IDIDResolutionResult['didResolutionMetadata'] = { error };
    if (problemDetails) {
      didResolutionMetadata.problemDetails = problemDetails;
      didResolutionMetadata.message = problemDetails.detail;
    }
    // Preserve the resolved document when the core produced one. A valid
    // earlier version can be returned alongside a warning-level error (e.g. an
    // explicit version selector that resolves cleanly while a later log entry
    // fails witness verification); dropping it would hide a legitimate result.
    return { didResolutionMetadata, didDocument, didDocumentMetadata };
  }

  return {
    didResolutionMetadata: { contentType: CONTENT_TYPE },
    didDocument,
    didDocumentMetadata,
  };
}
