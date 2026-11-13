import { PLACEHOLDER } from '../constants.js';
import { convertWebvhIdToWebId, generateParallelDidWeb } from '../did-document.js';
import type {
  CreateDIDInterface,
  CreateDIDResult,
  DeactivateDIDInterface,
  DIDDoc,
  DIDLog,
  DIDResolutionMeta,
  UpdateDIDInterface,
  UpdateDIDResult,
} from '../interfaces.js';
import {
  createDate,
  createNextVersionTime,
  MAX_FUTURE_SKEW_MS,
  validateUtcIso8601NotInFuture,
} from '../utils/iso8601-datetime.js';
import { normalizeCreateDidAddress, requireDidDocumentId, withNormalizedUpdateKeys } from '../utils.js';
import { createResolveVM } from '../vm-resolver.js';
import { prepareDeactivationEntry, prepareGenesisEntry, prepareUpdateEntry } from './method.v1.0.entries.js';
import { applyEntryToMeta } from './method.v1.0.meta.js';
import {
  type InternalResolutionOptions,
  resolveV1Log,
  type TraversedResolution,
  traverseV1Log,
} from './method.v1.0.resolution.js';
import { type MethodProfile, WEBVH_PROFILE } from './profile.js';

/**
 * `updateKeys` accepts Ed25519 multikeys or did:key identifiers (with an
 * optional matching fragment); entries and metadata always contain bare
 * multikeys.
 */
export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  // Parse address input with strict validation
  const addressInput = options.address;
  if (!addressInput) {
    throw new Error('Address must be provided');
  }

  const normalizedAddress = normalizeCreateDidAddress({
    address: addressInput,
    scid: PLACEHOLDER,
    paths: options.paths,
    context: 'createDID path segments',
  });
  return createDIDForController(options, normalizedAddress.controller, WEBVH_PROFILE);
};

/** The options that exist only for a method whose DID names a location. */
export const LOCATION_OPTIONS = ['address', 'paths', 'portable', 'alsoKnownAsWeb'] as const;

const assertLocationOptionsAllowed = (
  options: CreateDIDInterface | UpdateDIDInterface,
  profile: MethodProfile,
  operation: string
): void => {
  if (profile.hasLocation) {
    return;
  }
  const supplied = LOCATION_OPTIONS.filter((name) => options[name] !== undefined);
  if (supplied.length > 0) {
    throw new Error(`${operation} does not accept ${supplied.join(', ')}: a ${profile.method} DID names no location`);
  }
};

/**
 * Creates the first log entry for `controller`, the DID written with the
 * `{SCID}` placeholder. Shared by every method profile; the caller derives
 * `controller`. The checks every profile shares are made here: the `method`
 * option, the location options, and `updateKeys`, which is normalized.
 */
export const createDIDForController = async (
  options: CreateDIDInterface,
  controller: string,
  profile: MethodProfile
): Promise<CreateDIDResult> => {
  if (options.method && options.method !== profile.method) {
    throw new Error(`'${options.method}' is not a supported method version.`);
  }
  assertLocationOptionsAllowed(options, profile, 'createDID');
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied');
  }
  options = withNormalizedUpdateKeys(options);
  if (options.created) {
    validateUtcIso8601NotInFuture(options.created, 'createDID created');
  }
  const createdDate = createDate(options.created);

  const entry = await prepareGenesisEntry({
    options,
    controller,
    createdDate,
    profile,
  });

  const didId = requireDidDocumentId(entry.state.id);
  const webDoc = options.alsoKnownAsWeb ? generateParallelDidWeb(didId, entry.state) : undefined;

  return {
    did: didId,
    doc: entry.state,
    meta: applyEntryToMeta(entry, undefined, profile),
    log: [entry],
    ...(webDoc ? { webDoc } : {}),
  };
};

export const resolveDIDFromLog = async (
  log: DIDLog,
  options: InternalResolutionOptions = {}
): Promise<{ did: string; doc: DIDDoc | null; meta: DIDResolutionMeta }> => {
  // A fresh default resolver per resolution: did:webvh VM lookups memoize
  // within this resolution but nothing is trusted across resolutions.
  return resolveV1Log(log, { resolveVM: createResolveVM(options), ...options });
};

/** {@link resolveDIDFromLog}, also reporting how much of the log passed verification. */
export const traverseDIDLog = async (
  log: DIDLog,
  options: InternalResolutionOptions = {}
): Promise<TraversedResolution> => {
  return traverseV1Log(log, { resolveVM: createResolveVM(options), ...options });
};

/**
 * Resolves the metadata of the log an update or deactivation extends, unless
 * the caller supplied it as `priorMeta`. The options that affect resolution
 * (`verifier`, `witnessProofs`, `fetch`, `network`) are picked here, in one place, so a
 * new pass-through option cannot reach one operation and not the other.
 */
const resolvePriorMeta = async (
  log: DIDLog,
  {
    priorMeta,
    ...resolutionOptions
  }: Pick<UpdateDIDInterface, 'priorMeta' | 'verifier' | 'witnessProofs' | 'fetch' | 'network'>,
  profile: MethodProfile
): Promise<DIDResolutionMeta> => priorMeta ?? (await resolveDIDFromLog(log, { ...resolutionOptions, profile })).meta;

/**
 * Supplied `updateKeys` are normalized from Ed25519 multikeys or did:key
 * identifiers to bare multikeys before preparation, including pre-rotation
 * hash checks.
 */
export const updateDID = async (
  options: UpdateDIDInterface,
  profile: MethodProfile = WEBVH_PROFILE
): Promise<UpdateDIDResult> => {
  assertLocationOptionsAllowed(options, profile, 'updateDID');
  options = withNormalizedUpdateKeys(options);
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = await resolvePriorMeta(log, options, profile);
  const currentUpdateKeys = options.updateKeys;
  if (lastMeta.deactivated) {
    throw new Error('Cannot update deactivated DID');
  }
  if (lastMeta.prerotation && currentUpdateKeys === undefined) {
    throw new Error('updateKeys must be provided while pre-rotation is active');
  }
  const versionNumber = log.length + 1;
  // Validate user-provided timestamp with skew tolerance before creating the versionTime
  if (options.updated) {
    validateUtcIso8601NotInFuture(options.updated, 'updateDID updated', MAX_FUTURE_SKEW_MS);
  }
  const createdDate = createNextVersionTime(lastMeta.updated, options.updated);

  const entry = await prepareUpdateEntry({
    options,
    lastEntry,
    lastMeta,
    versionNumber,
    createdDate,
    profile,
  });

  const meta = applyEntryToMeta(entry, lastMeta);

  const updatedDidId = requireDidDocumentId(entry.state.id);
  const webDoc = options.alsoKnownAsWeb ? generateParallelDidWeb(updatedDidId, entry.state) : undefined;
  if (
    profile.hasLocation &&
    !options.alsoKnownAsWeb &&
    Array.isArray(entry.state.alsoKnownAs) &&
    entry.state.alsoKnownAs.includes(convertWebvhIdToWebId(updatedDidId))
  ) {
    // The document advertises the parallel did:web alias, but without
    // alsoKnownAsWeb no webDoc is generated -- a publisher that writes webDoc
    // on every update would otherwise silently serve a stale did:web document.
    console.warn(
      'updateDID: the DID document lists a parallel did:web alias but alsoKnownAsWeb was not passed, ' +
        'so no webDoc was generated. Pass alsoKnownAsWeb: true to keep the parallel did:web document current.'
    );
  }

  return {
    did: updatedDidId,
    doc: entry.state,
    meta,
    log: [...log, entry],
    ...(webDoc ? { webDoc } : {}),
  };
};

/**
 * Appends a deactivation entry, which writes `updateKeys: []` unless the
 * caller supplies `updateKeys`. Supplied `updateKeys` are normalized from
 * Ed25519 multikeys or did:key identifiers to bare multikeys before
 * preparation.
 *
 * A DID with pre-rotation active is refused: an entry under pre-rotation must
 * carry the pre-committed keys, so it cannot also empty `updateKeys`. Call
 * `updateDID` with `nextKeyHashes: []` first, then deactivate.
 */
export const deactivateDID = async (
  options: DeactivateDIDInterface,
  profile: MethodProfile = WEBVH_PROFILE
): Promise<{ did: string; doc: DIDDoc; meta: DIDResolutionMeta; log: DIDLog }> => {
  options = withNormalizedUpdateKeys(options);
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = await resolvePriorMeta(log, options, profile);
  if (lastMeta.deactivated) {
    throw new Error('DID already deactivated');
  }
  const versionNumber = log.length + 1;
  const createdDate = createNextVersionTime(lastMeta.updated, undefined);

  const entry = await prepareDeactivationEntry({
    options,
    lastEntry,
    lastMeta,
    versionNumber,
    createdDate,
  });

  const meta = applyEntryToMeta(entry, lastMeta);

  const didId = requireDidDocumentId(entry.state.id);

  return {
    did: didId,
    doc: entry.state,
    meta,
    log: [...log, entry],
  };
};
