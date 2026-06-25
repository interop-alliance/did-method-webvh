import type {
  CreateDIDInterface,
  CreateDIDResult,
  DeactivateDIDInterface,
  DIDLog,
  ResolutionOptions,
  ServiceEndpoint,
  UpdateDIDInterface,
  UpdateDIDResult,
  WitnessProofFileEntry,
} from './interfaces.js';
import { DidResolutionError } from './interfaces.js';
import * as v1 from './method_versions/method.v1.0.js';
import { fetchLogFromIdentifier, maybeWriteTestLog } from './utils.js';

const SUPPORTED_METHOD = 'did:webvh:1.0';

/**
 * Creates a new did:webvh DID and initial DID log.
 *
 * @param options DID creation options.
 * @returns The created DID, resolved document, and DID log.
 */
export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  const method = (options as { method?: string }).method;
  if (method && method !== SUPPORTED_METHOD) {
    throw new Error(`'${method}' is not a supported method version.`);
  }
  const result = await v1.createDID(options);
  maybeWriteTestLog(result.did, result.log);
  return result;
};

/**
 * Resolves a DID by fetching and validating its DID log.
 *
 * @param did The DID to resolve.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata.
 */
export const resolveDID = async (
  did: string,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
) => {
  // Extract the expected SCID from the DID string so the resolver can
  // verify the log's SCID matches what the DID claims.
  const didParts = did.split(':');
  const scid = didParts.length > 2 && didParts[0] === 'did' && didParts[1] === 'webvh' ? didParts[2] : undefined;
  try {
    const log = await fetchLogFromIdentifier(did);
    const result = await v1.resolveDIDFromLog(log, { ...options, scid, requestedDid: did });
    maybeWriteTestLog(result.did, log);

    return result;
  } catch (e) {
    let errorType: DidResolutionError = DidResolutionError.InvalidDid;
    const message = e instanceof Error ? e.message : String(e);
    if (/not found/i.test(message) || /404/.test(message)) {
      errorType = DidResolutionError.NotFound;
    }
    return {
      did,
      doc: null,
      meta: {
        error: errorType,
        problemDetails: {
          type:
            errorType === DidResolutionError.NotFound
              ? 'https://w3id.org/security#NOT_FOUND'
              : 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
          title:
            errorType === DidResolutionError.NotFound
              ? 'The DID Log or resource was not found.'
              : 'The resolved DID is invalid.',
          detail: message,
        },
      },
    };
  }
};

/**
 * Resolves a DID from an in-memory DID log.
 *
 * @param log In-memory DID log entries.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata.
 */
export const resolveDIDFromLog = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
) => {
  const result = await v1.resolveDIDFromLog(log, options);
  maybeWriteTestLog(result.did, log);
  return result;
};

/**
 * Updates an existing DID log with a new entry.
 *
 * @param options DID update options.
 * @returns The updated DID, resolved document, and DID log.
 */
export const updateDID = async (
  options: UpdateDIDInterface & {
    services?: ServiceEndpoint[];
    domain?: string;
    address?: string;
    paths?: string[];
    updated?: string;
  }
): Promise<UpdateDIDResult> => {
  const result = await v1.updateDID(options);
  maybeWriteTestLog(result.did, result.log);
  return result;
};

/**
 * Deactivates an existing DID by appending a deactivation entry.
 *
 * @param options DID deactivation options.
 * @returns The deactivated DID result and updated DID log.
 */
export const deactivateDID = async (options: DeactivateDIDInterface & { updateKeys?: string[] }) => {
  const result = await v1.deactivateDID(options);
  maybeWriteTestLog(result.did, result.log);
  return result;
};
