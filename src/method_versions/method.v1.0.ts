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
import { validateWitnessParameter } from '../witness.js';
import { prepareDeactivationEntry, prepareGenesisEntry, prepareUpdateEntry } from './method.v1.0.entries.js';
import { applyEntryToMeta } from './method.v1.0.meta.js';
import { type InternalResolutionOptions, resolveV1Log } from './method.v1.0.resolution.js';

/**
 * `updateKeys` accepts Ed25519 multikeys or did:key identifiers (with an
 * optional matching fragment); entries and metadata always contain bare
 * multikeys.
 */
export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied');
  }
  options = withNormalizedUpdateKeys(options);

  validateWitnessParameter(options.witness);

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
  const controller = normalizedAddress.controller;
  if (options.created) {
    validateUtcIso8601NotInFuture(options.created, 'createDID created');
  }
  const createdDate = createDate(options.created);

  const entry = await prepareGenesisEntry({
    options,
    controller,
    createdDate,
  });

  const didId = requireDidDocumentId(entry.state.id);
  const webDoc = options.alsoKnownAsWeb ? generateParallelDidWeb(didId, entry.state) : undefined;

  return {
    did: didId,
    doc: entry.state,
    meta: applyEntryToMeta(entry),
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

/**
 * Resolves the metadata of the log an update or deactivation extends, unless
 * the caller supplied it as `priorMeta`. The options that affect resolution
 * (`verifier`, `witnessProofs`, `fetch`) are picked here, in one place, so a
 * new pass-through option cannot reach one operation and not the other.
 */
const resolvePriorMeta = async (
  log: DIDLog,
  { priorMeta, ...resolutionOptions }: Pick<UpdateDIDInterface, 'priorMeta' | 'verifier' | 'witnessProofs' | 'fetch'>
): Promise<DIDResolutionMeta> => priorMeta ?? (await resolveDIDFromLog(log, resolutionOptions)).meta;

/**
 * Supplied `updateKeys` are normalized from Ed25519 multikeys or did:key
 * identifiers to bare multikeys before preparation, including pre-rotation
 * hash checks.
 */
export const updateDID = async (options: UpdateDIDInterface): Promise<UpdateDIDResult> => {
  options = withNormalizedUpdateKeys(options);
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = await resolvePriorMeta(log, options);
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
  });

  const meta = applyEntryToMeta(entry, lastMeta);

  const updatedDidId = requireDidDocumentId(entry.state.id);
  const webDoc = options.alsoKnownAsWeb ? generateParallelDidWeb(updatedDidId, entry.state) : undefined;
  if (
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
 * Supplied `updateKeys` are normalized from Ed25519 multikeys or did:key
 * identifiers to bare multikeys before preparation, including pre-rotation
 * hash checks.
 */
export const deactivateDID = async (
  options: DeactivateDIDInterface
): Promise<{ did: string; doc: DIDDoc; meta: DIDResolutionMeta; log: DIDLog }> => {
  options = withNormalizedUpdateKeys(options);
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = await resolvePriorMeta(log, options);
  if (lastMeta.deactivated) {
    throw new Error('DID already deactivated');
  }
  if (lastMeta.prerotation && options.updateKeys === undefined) {
    throw new Error('updateKeys must be provided while pre-rotation is active');
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
