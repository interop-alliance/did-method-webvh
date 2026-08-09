import type { IDIDResolutionResult } from '@interop/data-integrity-core';
import { METHOD_PROTOCOL_V1_0 } from './constants.js';
import type {
  CreateDIDInterface,
  CreateDIDResult,
  DeactivateDIDInterface,
  DIDLog,
  ResolutionOptions,
  UpdateDIDInterface,
  UpdateDIDResult,
} from './interfaces.js';
import * as v1 from './method_versions/method.v1.0.js';
import { mapErrorToCode, toErrorResult, toResolutionResult, validateResolutionSelectors } from './resolver-result.js';
import { fetchLogFromIdentifier, parseDidWebvhIdentifier } from './utils.js';
import { defaultWebvhLogVerifier } from './verifier.js';

/**
 * Creates a new did:webvh DID and initial DID log.
 *
 * @param options DID creation options.
 * @returns The created DID, resolved document, and DID log.
 */
export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  const method = options.method;
  if (method && method !== METHOD_PROTOCOL_V1_0) {
    throw new Error(`'${method}' is not a supported method version.`);
  }
  options.verifier ??= defaultWebvhLogVerifier;
  return v1.createDID(options);
};

/**
 * Resolves a DID by fetching and validating its DID log.
 *
 * Returns a DID Resolution spec result envelope: on failure, `didDocument` is
 * `null` and the reason is on `didResolutionMetadata.error` (with RFC 9457
 * `problemDetails`); document metadata (`versionId`, `scid`, `updateKeys`,
 * etc.) is on `didDocumentMetadata`.
 *
 * @param did The DID to resolve.
 * @param options Optional resolver settings.
 * @returns The DID resolution result envelope.
 */
export const resolveDID = async (did: string, options: ResolutionOptions = {}): Promise<IDIDResolutionResult> => {
  // Extract the expected SCID from the DID string so the resolver can
  // verify the log's SCID matches what the DID claims. A malformed DID leaves
  // it undefined; the fetch below then reports the parse failure.
  let scid: string | undefined;
  try {
    scid = parseDidWebvhIdentifier(did, 'did').scid;
  } catch {}
  const verifier = options.verifier ?? defaultWebvhLogVerifier;
  const selectorError = validateResolutionSelectors(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, selectorError.problemType);
  }
  try {
    const log = await fetchLogFromIdentifier(did);
    const result = await v1.resolveDIDFromLog(log, { ...options, verifier, scid, requestedDid: did });

    return toResolutionResult(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message);
  }
};

/**
 * Resolves a DID from an in-memory DID log.
 *
 * Returns this package's core result shape (`{ did, doc, meta }`, with a flat
 * `meta` combining document state and control parameters), which suits
 * DID-management tooling acting on the log (key rotation, updates, repair).
 * Callers relaying the outcome to a DID Resolution spec interface can convert
 * it with {@link toResolutionResult}.
 *
 * @param log In-memory DID log entries.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata.
 */
export const resolveDIDFromLog = async (log: DIDLog, options: ResolutionOptions = {}) => {
  const verifier = options.verifier ?? defaultWebvhLogVerifier;
  return v1.resolveDIDFromLog(log, { ...options, verifier });
};

/**
 * Updates an existing DID log with a new entry.
 *
 * Overlay semantics: the prior entry's DID document is carried forward and only
 * the fields this call supplies are overwritten. `@context`, `id`, and
 * `controller` are always re-derived. Verification-method fields
 * (`verificationMethod` and the relationship arrays) are preserved unless
 * `verificationMethods` is supplied; `service`, `alsoKnownAs`, and the
 * individual relationship options overwrite only when explicitly passed. A
 * key-only update (`updateKeys` + `nextKeyHashes`, no document directives) thus
 * preserves the prior document verbatim -- the load-bearing contract for
 * rotation ceremonies.
 *
 * @param options DID update options.
 * @returns The updated DID, resolved document, and DID log.
 */
export const updateDID = async (options: UpdateDIDInterface): Promise<UpdateDIDResult> => {
  options.verifier ??= defaultWebvhLogVerifier;
  return v1.updateDID(options);
};

/**
 * Deactivates an existing DID by appending a deactivation entry.
 *
 * @param options DID deactivation options.
 * @returns The deactivated DID result and updated DID log.
 */
export const deactivateDID = async (options: DeactivateDIDInterface) => {
  options.verifier ??= defaultWebvhLogVerifier;
  return v1.deactivateDID(options);
};
