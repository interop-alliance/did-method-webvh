import { isDIDResolutionError } from '@interop/data-integrity-core';
import { assertDefinedParameters, documentStateIsValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions.js';
import { DEFAULT_TTL_SECONDS, PLACEHOLDER } from '../constants.js';
import { findVerificationMethod } from '../did-document.js';
import type {
  DIDDoc,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  ResolutionOptions,
  ResolveVerificationMethod,
  WitnessParameter,
  WitnessProofFileEntry,
} from '../interfaces.js';
import { toErrorMeta, validateResolutionSelectors } from '../resolver-result.js';
import { deriveHash } from '../utils/crypto.js';
import { MAX_FUTURE_SKEW_MS, validateUtcIso8601NotInFuture } from '../utils/iso8601-datetime.js';
import {
  buildVersionId,
  loadWitnessProofs,
  parseAndValidateVersionId,
  replaceValueInObject,
  requireDidDocumentId,
} from '../utils.js';
import {
  countVerifiedWitnessApprovals,
  hasActiveWitnessRequirement,
  resolveWitnessParameter,
  validateWitnessParameter,
} from '../witness.js';
import { applyEntryToMeta } from './method.v1.0.meta.js';
import { type MethodProfile, type ParsedStateId, WEBVH_PROFILE } from './profile.js';

// The default VM resolver lives above this module (`vm-resolver.ts` needs full
// log resolution), so the method layer injects it via options.
const requireResolveVM = (options: ResolutionOptions): ResolveVerificationMethod => {
  if (!options.resolveVM) {
    throw new Error('resolveVM implementation is required');
  }
  return options.resolveVM;
};

/** A required-witness threshold that was not met during resolution. */
export class WitnessThresholdError extends Error {
  /** The number of the version whose threshold was not met. */
  versionNumber: number;

  constructor(message: string, versionNumber: number) {
    super(message);
    this.versionNumber = versionNumber;
  }
}

interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameter;
}

interface ResolutionSnapshot {
  did: string;
  doc: DIDDoc | null;
  meta: DIDResolutionMeta;
  /** The 1-based number of log entries this snapshot reflects. */
  versionNumber: number;
}

interface ResolverContext {
  meta: DIDResolutionMeta;
  host: string;
  previousVersionTime: Date | undefined;
  resolvedSnapshot: ResolutionSnapshot | null;
  lastValidSnapshot: ResolutionSnapshot | null;
  /** One snapshot per validated entry, in log order. */
  snapshots: ResolutionSnapshot[];
  requiredWitnessChecks: RequiredWitnessCheck[];
  didIdMatched: boolean;
}

interface ParsedResolutionEntryContext {
  entry: DIDLogEntry;
  parsedVersion: {
    versionNumber: number;
    entryHash: string;
  };
  currentVersionTime: Date;
  parsedStateDid: ParsedStateId;
}

/**
 * Public resolution options plus the requested-DID hint `resolveDID` sets for
 * itself, and the method profile the log is read under (did:webvh when
 * omitted).
 */
export type InternalResolutionOptions = ResolutionOptions & {
  requestedDid?: string;
  profile?: MethodProfile;
  /**
   * Supplies the witness proofs when a version requires them, in place of
   * `witnessProofs` and the fetch derived from the DID. Called at most once,
   * and not at all for a log that requires no witnesses.
   */
  loadWitnessProofs?: () => Promise<WitnessProofFileEntry[]>;
  /**
   * Resolve to the valid entries when a later entry fails verification. With
   * no version selector the result is the last valid entry. An entry whose
   * witness threshold is not met counts as failing verification, so the valid
   * entries end before it. When unset, both cases fail resolution (an unmet
   * threshold decorates a historical snapshot).
   */
  returnLastValidEntry?: boolean;
};

/** The core resolution result, with what the traversal found about the log. */
export interface TraversedResolution {
  did: string;
  doc: DIDDoc | null;
  meta: DIDResolutionMeta;
  /** The number of entries that passed verification. */
  validEntryCount: number;
  /** The metadata as of the last valid entry. */
  lastValidMeta: DIDResolutionMeta;
  /** The error of the first entry that failed verification, if any. */
  invalidEntryError?: unknown;
}

const profileOf = (options: InternalResolutionOptions): MethodProfile => options.profile ?? WEBVH_PROFILE;

export const resolveV1Log = async (
  log: DIDLog,
  options: InternalResolutionOptions = {}
): Promise<{ did: string; doc: DIDDoc | null; meta: DIDResolutionMeta }> => {
  const { did, doc, meta } = await traverseV1Log(log, options);
  return { did, doc, meta };
};

/** Resolves `log` and also reports how much of it passed verification. */
export const traverseV1Log = async (
  log: DIDLog,
  options: InternalResolutionOptions = {}
): Promise<TraversedResolution> => {
  // Stage 1: initialize resolution input and context.
  const selectorError = validateResolutionSelectors(options);
  if (selectorError) {
    throw new Error(selectorError.detail);
  }
  assertSupportedLog(log, profileOf(options));
  const resolverContext = createInitialResolverContext(profileOf(options));
  const hasExplicitHistoricalSelector =
    options.versionNumber !== undefined ||
    options.versionId !== undefined ||
    options.versionTime !== undefined ||
    options.verificationMethod !== undefined;

  let invalidEntryError: unknown;

  // Stage 2: process log entries. A historical selector may keep the snapshot
  // it already latched when a later entry is invalid; the snapshot was itself
  // valid, so the later entry's error does not taint it.
  try {
    await processResolvedLogEntries({
      resolverContext,
      logEntries: log,
      options,
    });
  } catch (e) {
    const unsupported = isDIDResolutionError(e) && e.code === 'featureNotSupported';
    // A retrieval or internal failure says nothing about the entry, so it is
    // not treated as an entry failing verification.
    if (options.returnLastValidEntry && isDIDResolutionError(e) && !unsupported) {
      throw e;
    }
    if (!resolverContext.resolvedSnapshot) {
      // With no selector, the caller may ask for the last valid entry. An
      // unsupported method version is the exception: the entries that could
      // not be read may change the document or its keys.
      const fallsBack =
        options.returnLastValidEntry &&
        !hasExplicitHistoricalSelector &&
        resolverContext.lastValidSnapshot !== null &&
        !unsupported;
      if (!fallsBack) {
        throw e;
      }
    }
    invalidEntryError = e;
  }

  // Stage 3: post-traversal invariants and witness enforcement. These run
  // outside the try above so a witness retrieval failure is never swallowed
  // by the historical fallback. After a failed traversal they cover only the
  // validated prefix, and only the versions up to the selected one.
  // An unmet threshold found here comes before any entry that failed above.
  invalidEntryError =
    (await finalizeResolutionChecks({ resolverContext, logEntries: log, options })) ?? invalidEntryError;

  // Stage 4: finalize fallback selection and shape the response.
  let resolvedSnapshot = resolverContext.resolvedSnapshot;
  const lastValidSnapshot = resolverContext.lastValidSnapshot;
  if (!lastValidSnapshot) {
    throw new Error('DID resolution failed: No valid metadata found');
  }
  const traversal = {
    validEntryCount: lastValidSnapshot.versionNumber,
    lastValidMeta: lastValidSnapshot.meta,
    invalidEntryError,
  };

  if (!resolvedSnapshot && hasExplicitHistoricalSelector) {
    return {
      ...traversal,
      did: lastValidSnapshot.did,
      doc: null,
      meta: {
        ...lastValidSnapshot.meta,
        ...toErrorMeta(
          'notFound',
          'The supplied explicit version selector did not match any entry in the DID log.',
          undefined,
          'The requested DID version was not found.'
        ),
      },
    };
  }

  if (!resolvedSnapshot) {
    resolvedSnapshot = lastValidSnapshot.meta.deactivated ? { ...lastValidSnapshot, doc: null } : lastValidSnapshot;
  }

  if (!resolvedSnapshot.did) {
    throw new Error('DID resolution failed: No valid identifier found');
  }

  // Deactivation is DID-global state. A historical selector keeps the
  // historical document while still reporting deactivated: true when the
  // log's final state is deactivated; non-historical resolution nulls the
  // document as before.
  if (hasExplicitHistoricalSelector) {
    if (lastValidSnapshot.meta.deactivated) {
      resolvedSnapshot = markResolvedSnapshotDeactivated({ resolvedSnapshot, resolverContext });
    }
  } else if (resolvedSnapshot.meta.deactivated) {
    resolvedSnapshot = markResolvedSnapshotDeactivated({ resolvedSnapshot, resolverContext });
    return {
      ...traversal,
      did: resolvedSnapshot.did,
      doc: null,
      meta: resolvedSnapshot.meta,
    };
  }

  if (!resolvedSnapshot.doc) {
    throw new Error('DID resolution failed: No valid document found');
  }

  return {
    ...traversal,
    did: resolvedSnapshot.did,
    // Snapshots reference the caller's log entry state; clone the escaping
    // document so the result never aliases the log.
    doc: structuredClone(resolvedSnapshot.doc),
    meta: resolvedSnapshot.meta,
  };
};

const markResolvedSnapshotDeactivated = ({
  resolvedSnapshot,
  resolverContext,
}: {
  resolvedSnapshot: ResolutionSnapshot;
  resolverContext: ResolverContext;
}): ResolutionSnapshot => {
  const nextSnapshot: ResolutionSnapshot = {
    ...resolvedSnapshot,
    meta: {
      ...resolvedSnapshot.meta,
      deactivated: true,
    },
  };
  resolverContext.resolvedSnapshot = nextSnapshot;
  return nextSnapshot;
};

const processResolvedLogEntries = async ({
  resolverContext,
  logEntries,
  options,
}: {
  resolverContext: ResolverContext;
  logEntries: DIDLog;
  options: InternalResolutionOptions;
}): Promise<void> => {
  // Process each log entry in order and update resolution context.
  const profile = profileOf(options);
  for (let entryIndex = 0; entryIndex < logEntries.length; entryIndex++) {
    // Deactivation is terminal: a validly signed entry appended afterwards
    // must not become the latest state.
    if (resolverContext.meta.deactivated) {
      throw new Error(`Log entry '${logEntries[entryIndex].versionId}' follows a deactivation entry`);
    }
    if (profile.emptyUpdateKeysEndLog && entryIndex > 0 && resolverContext.meta.updateKeys.length === 0) {
      throw new Error(`Log entry '${logEntries[entryIndex].versionId}' follows an entry that set updateKeys to []`);
    }

    // A later entry's `method` is read before anything else in it. An entry
    // of a version this code does not implement cannot be judged by these
    // rules, so no other check may report on it first. A value that is not
    // a string is left to the parameter type check.
    if (entryIndex > 0) {
      const method: unknown = logEntries[entryIndex]?.parameters?.method;
      if (typeof method === 'string' && method !== profile.method) {
        throw profile.unsupportedMethodError(method, entryIndex + 1);
      }
    }

    const entryContext = validateAndParseLogEntry({
      entry: logEntries[entryIndex],
      expectedVersionNumber: entryIndex + 1,
      previousVersionTime: resolverContext.previousVersionTime,
      profile,
    });
    const {
      entry: { versionId, versionTime, parameters },
      parsedVersion: { versionNumber },
    } = entryContext;

    const previousWitness = resolverContext.meta.witness;
    resolverContext.meta.versionId = versionId;
    resolverContext.previousVersionTime = entryContext.currentVersionTime;
    resolverContext.meta.versionTime = versionTime;
    resolverContext.meta.updated = versionTime;

    const resolvedEntryDoc =
      versionNumber === 1
        ? await processV1GenesisEntry({ resolverContext, entryContext, options })
        : await processV1SubsequentEntry({
            resolverContext,
            entryContext,
            logEntries,
            entryIndex,
            options,
          });

    const requiredWitness = getRequiredWitnessForEntry(previousWitness, parameters, resolverContext.meta.witness);
    if (requiredWitness) {
      resolverContext.requiredWitnessChecks.push({
        targetVersionId: resolverContext.meta.versionId,
        targetVersionNumber: versionNumber,
        witness: requiredWitness,
      });
    }

    // Snapshots hold a reference into the caller's log; the one document that
    // escapes resolveV1Log is cloned at the return boundary, so no per-entry
    // deep clone is needed here.
    const doc = resolvedEntryDoc;
    const did = requireDidDocumentId(doc.id);

    if (options.requestedDid && did === options.requestedDid) {
      resolverContext.didIdMatched = true;
    }

    // Latch the first entry matching the requested selector as the resolved result.
    let matchesSelector =
      (!!options.verificationMethod && !!findVerificationMethod(doc, options.verificationMethod)) ||
      options.versionNumber === versionNumber ||
      options.versionId === resolverContext.meta.versionId;
    if (!matchesSelector && options.versionTime && options.versionTime >= entryContext.currentVersionTime) {
      // The next entry's versionTime is parsed here only when a versionTime
      // selector is in play; the next iteration's strict validation is the
      // canonical parse.
      // An unparseable next versionTime is treated as no next entry; the
      // next iteration rejects that entry, and the snapshot latched here
      // is what a historical selector then falls back to.
      const nextVersionTime = Date.parse(logEntries[entryIndex + 1]?.versionTime);
      matchesSelector = Number.isNaN(nextVersionTime) || options.versionTime.getTime() < nextVersionTime;
    }

    const snapshot: ResolutionSnapshot = {
      doc,
      did,
      meta: { ...resolverContext.meta },
      versionNumber,
    };
    if (matchesSelector && !resolverContext.resolvedSnapshot) {
      resolverContext.resolvedSnapshot = snapshot;
    }
    resolverContext.lastValidSnapshot = snapshot;
    resolverContext.snapshots.push(snapshot);
  }
};

/**
 * Runs the post-traversal checks. Returns the unmet-threshold error when
 * `returnLastValidEntry` shortened the valid entries because of it, and
 * `undefined` otherwise.
 */
const finalizeResolutionChecks = async ({
  resolverContext,
  logEntries,
  options,
}: {
  resolverContext: ResolverContext;
  logEntries: DIDLog;
  options: InternalResolutionOptions;
}): Promise<WitnessThresholdError | undefined> => {
  if (options.requestedDid && !resolverContext.didIdMatched) {
    throw new Error(`Requested DID '${options.requestedDid}' does not match state.id in any valid log version`);
  }

  const { resolvedSnapshot, lastValidSnapshot } = resolverContext;
  if (!lastValidSnapshot) {
    return undefined;
  }

  // After a successful traversal every version is enforced, so a later
  // version's unmet threshold decorates a historical snapshot. After a failed
  // traversal only the selected version and its predecessors are enforced;
  // the entries between it and the invalid one were validated but the log
  // as published is broken, so their thresholds are not held against the
  // selected version. With `returnLastValidEntry` every validated version is
  // enforced, to find the first one whose threshold is not met.
  const logTraversalSucceeded = lastValidSnapshot.versionNumber === logEntries.length;
  const maxVersionNumber =
    options.returnLastValidEntry || logTraversalSucceeded || !resolvedSnapshot
      ? lastValidSnapshot.versionNumber
      : resolvedSnapshot.versionNumber;
  try {
    await enforceWitnessChecksUpTo({ resolverContext, lastValidSnapshot, logEntries, options, maxVersionNumber });
  } catch (e) {
    if (!(e instanceof WitnessThresholdError)) {
      throw e;
    }
    if (options.returnLastValidEntry) {
      // The version fails verification, so the valid entries end before it.
      // Nothing is left when it is the first version, and a selected version
      // at or after it is not a valid entry.
      const selectedIsInvalid = resolvedSnapshot !== null && resolvedSnapshot.versionNumber >= e.versionNumber;
      if (e.versionNumber === 1 || selectedIsInvalid) {
        throw e;
      }
      resolverContext.snapshots.length = e.versionNumber - 1;
      resolverContext.lastValidSnapshot = resolverContext.snapshots[e.versionNumber - 2];
      return e;
    }
    // A historical snapshot survives an unmet threshold but reports it.
    if (!resolvedSnapshot) {
      throw e;
    }
    Object.assign(resolvedSnapshot.meta, toErrorMeta('invalidDid', e.message));
  }
  return undefined;
};

/**
 * Enforces the collected witness checks whose target version is at most
 * `maxVersionNumber`, over the validated prefix of the log. Checks are only
 * collected for validated entries, so proofs over a never-validated entry do
 * not count. Proofs published for a later validated version still count
 * toward an earlier one.
 */
const enforceWitnessChecksUpTo = async ({
  resolverContext,
  lastValidSnapshot,
  logEntries,
  options,
  maxVersionNumber,
}: {
  resolverContext: ResolverContext;
  lastValidSnapshot: ResolutionSnapshot;
  logEntries: DIDLog;
  options: InternalResolutionOptions;
  maxVersionNumber: number;
}): Promise<void> => {
  const requiredWitnessChecks = resolverContext.requiredWitnessChecks.filter(
    (check) => check.targetVersionNumber <= maxVersionNumber
  );
  if (requiredWitnessChecks.length === 0) {
    return;
  }
  await enforceRequiredWitnessChecks({
    requiredWitnessChecks,
    options,
    did: lastValidSnapshot.did,
    logEntries: logEntries.slice(0, lastValidSnapshot.versionNumber),
  });
};

/**
 * Validates a witness-signing candidate log and returns the witness
 * requirement governing its final entry.
 *
 * The whole candidate is resolved (structure, hash chain, controller proofs,
 * deactivation), and the witness thresholds of every entry before the final
 * one are enforced. The final entry's own threshold is not enforced, since
 * the caller is about to contribute a proof toward it. Returns `undefined`
 * when no active witness requirement governs the final entry.
 */
export const resolveWitnessCandidateRequirement = async (
  candidateLog: DIDLog,
  options: InternalResolutionOptions
): Promise<WitnessParameter | undefined> => {
  assertSupportedLog(candidateLog, profileOf(options));
  const resolverContext = createInitialResolverContext(profileOf(options));
  await processResolvedLogEntries({ resolverContext, logEntries: candidateLog, options });
  const { lastValidSnapshot } = resolverContext;
  if (!lastValidSnapshot) {
    return undefined;
  }

  const candidateVersionNumber = candidateLog.length;
  await enforceWitnessChecksUpTo({
    resolverContext,
    lastValidSnapshot,
    logEntries: candidateLog,
    options,
    maxVersionNumber: candidateVersionNumber - 1,
  });

  return resolverContext.requiredWitnessChecks.find((check) => check.targetVersionNumber === candidateVersionNumber)
    ?.witness;
};

const assertHashChain = (recomputedHash: string, entryHash: string, versionId: string): void => {
  if (recomputedHash !== entryHash) {
    throw new Error(`Hash chain broken at '${versionId}'`);
  }
};

const assertSupportedLog = (log: DIDLog, profile: MethodProfile): void => {
  if (log.length === 0) {
    throw new Error(`Log identity binding check failed: no entries to process`);
  }
  const protocol = log[0]?.parameters?.method;
  if (protocol !== profile.method) {
    throw profile.unsupportedMethodError(protocol);
  }
};

const createInitialResolverContext = (profile: MethodProfile): ResolverContext => {
  return {
    meta: {
      versionId: '',
      versionTime: '',
      created: '',
      updated: '',
      deactivated: false,
      ...(profile.hasLocation ? { portable: false } : {}),
      ttl: DEFAULT_TTL_SECONDS,
      scid: '',
      updateKeys: [],
      nextKeyHashes: [],
      prerotation: false,
      witness: undefined,
      watchers: [],
    },
    host: '',
    previousVersionTime: undefined,
    resolvedSnapshot: null,
    lastValidSnapshot: null,
    snapshots: [],
    requiredWitnessChecks: [],
    didIdMatched: false,
  };
};

const validateAndParseLogEntry = ({
  entry,
  expectedVersionNumber,
  previousVersionTime,
  profile,
}: {
  entry: DIDLogEntry;
  expectedVersionNumber: number;
  previousVersionTime: Date | undefined;
  profile: MethodProfile;
}): ParsedResolutionEntryContext => {
  const { versionId, versionTime } = entry;
  const { version, versionNumber, entryHash } = parseAndValidateVersionId(versionId, expectedVersionNumber);
  assertDefinedParameters(entry.parameters, version, profile);

  if (!versionTime) {
    throw new Error(`version '${version}' is missing versionTime`);
  }

  // Check against resolver's current time for each entry per spec normative language
  const currentVersionTime = validateUtcIso8601NotInFuture(
    versionTime,
    `version '${version}' versionTime`,
    MAX_FUTURE_SKEW_MS
  );
  if (profile.wholeSecondVersionTime && versionTime.includes('.')) {
    throw new Error(`version '${version}' versionTime must be in whole seconds`);
  }
  if (previousVersionTime && currentVersionTime.getTime() <= previousVersionTime.getTime()) {
    throw new Error(`versionTime for version '${version}' must be greater than previous entry time`);
  }

  const parsedStateDid = profile.parseStateId(requireDidDocumentId(entry.state.id), `version '${version}' state.id`);

  return {
    entry,
    parsedVersion: {
      versionNumber,
      entryHash,
    },
    currentVersionTime,
    parsedStateDid,
  };
};

const processV1GenesisEntry = async ({
  resolverContext,
  entryContext,
  options,
}: {
  resolverContext: ResolverContext;
  entryContext: ParsedResolutionEntryContext;
  options: InternalResolutionOptions;
}): Promise<DIDDoc> => {
  const {
    entry: sourceEntry,
    parsedVersion: { entryHash },
    parsedStateDid,
  } = entryContext;
  const { parameters, proof } = sourceEntry;

  // applyEntryToMeta enforces the genesis invariant (non-empty scid/updateKeys)
  // via parseGenesisParameters.
  resolverContext.meta = applyEntryToMeta(sourceEntry, undefined, profileOf(options));
  resolverContext.host = parsedStateDid.locationKey;
  if (options.scid && options.scid !== resolverContext.meta.scid) {
    throw new Error(`SCID in DID '${options.scid}' does not match SCID in log '${resolverContext.meta.scid}'`);
  }
  validateWitnessParameter(resolverContext.meta.witness);

  // Optimized: Use efficient object manipulation instead of JSON stringify/parse
  const logEntry = {
    versionId: PLACEHOLDER,
    versionTime: resolverContext.meta.created,
    parameters: replaceValueInObject(parameters, resolverContext.meta.scid, PLACEHOLDER),
    state: replaceValueInObject(sourceEntry.state, resolverContext.meta.scid, PLACEHOLDER),
  };

  const logEntryHash = await deriveHash(logEntry);
  if (!(await scidIsFromHash(resolverContext.meta.scid, logEntryHash))) {
    throw new Error(`SCID '${resolverContext.meta.scid}' not derived from logEntryHash '${logEntryHash}'`);
  }

  if (parsedStateDid.scid !== resolverContext.meta.scid) {
    throw new Error(
      `SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${resolverContext.meta.scid}'`
    );
  }

  // Optimized: Direct object manipulation instead of JSON stringify/parse
  const prelimEntry = replaceValueInObject(logEntry, PLACEHOLDER, resolverContext.meta.scid);

  const logEntryHash2 = await deriveHash(prelimEntry);
  // The published versionId must carry the derived entry hash, as it does for
  // every later entry; a valid SCID and proof alone do not bind it.
  assertHashChain(logEntryHash2, entryHash, resolverContext.meta.versionId);
  const verified = await documentStateIsValid(
    { ...prelimEntry, versionId: buildVersionId(1, logEntryHash2), proof },
    {
      updateKeys: resolverContext.meta.updateKeys,
      verifier: options.verifier,
      resolveVM: requireResolveVM(options),
    }
  );
  if (!verified) {
    throw new Error(`version ${resolverContext.meta.versionId} failed verification of the proof.`);
  }

  return sourceEntry.state;
};

const processV1SubsequentEntry = async ({
  resolverContext,
  entryContext,
  logEntries,
  entryIndex,
  options,
}: {
  resolverContext: ResolverContext;
  entryContext: ParsedResolutionEntryContext;
  logEntries: DIDLog;
  entryIndex: number;
  options: InternalResolutionOptions;
}): Promise<DIDDoc> => {
  const {
    entry: sourceEntry,
    parsedVersion: { versionNumber, entryHash },
    parsedStateDid,
  } = entryContext;
  const { parameters } = sourceEntry;
  const profile = profileOf(options);

  // scid MUST NOT appear in later entries
  if ('scid' in parameters) {
    throw new Error(`version '${versionNumber}' must not contain SCID parameter`);
  }

  // portable: true cannot be introduced after the first entry -- it can only remain
  // true if it was already enabled in the first entry
  if (parameters.portable === true && !resolverContext.meta.portable) {
    throw new Error(
      `version '${versionNumber}' cannot set portable: true; portability can only be enabled in the first entry`
    );
  }

  // Setting portable: false in a later entry permanently locks portability off
  if (parameters.portable === false) {
    resolverContext.meta.portable = false;
  }

  if (parsedStateDid.scid !== resolverContext.meta.scid) {
    throw new Error(
      `SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${resolverContext.meta.scid}'`
    );
  }

  const newLocation = parsedStateDid.locationKey;
  if (newLocation !== resolverContext.host) {
    if (!resolverContext.meta.portable) {
      throw new Error('Cannot move DID: portability is disabled');
    }
    resolverContext.host = newLocation;
  }

  // Hash chain
  const { proof: _proof, ...entryWithoutProof } = logEntries[entryIndex];
  const recomputedHash = await deriveHash({ ...entryWithoutProof, versionId: logEntries[entryIndex - 1].versionId });
  assertHashChain(recomputedHash, entryHash, resolverContext.meta.versionId);

  // Signature verification
  let keys: string[];
  if (resolverContext.meta.prerotation) {
    if (!Array.isArray(parameters.updateKeys)) {
      throw new Error(`version '${versionNumber}' must declare updateKeys while pre-rotation is active`);
    }
    if (profile.prerotationRequiresNextKeyHashes && !Array.isArray(parameters.nextKeyHashes)) {
      throw new Error(`version '${versionNumber}' must declare nextKeyHashes while pre-rotation is active`);
    }
    keys = parameters.updateKeys;
  } else {
    keys = resolverContext.meta.updateKeys;
  }
  const verified = await documentStateIsValid(logEntries[entryIndex], {
    updateKeys: keys,
    verifier: options.verifier,
    resolveVM: requireResolveVM(options),
  });
  if (!verified) {
    throw new Error(`version ${resolverContext.meta.versionId} failed verification of the proof.`);
  }

  if (resolverContext.meta.prerotation) {
    await newKeysAreInNextKeys(parameters.updateKeys ?? [], resolverContext.meta.nextKeyHashes ?? []);
  }

  resolverContext.meta = applyEntryToMeta(sourceEntry, resolverContext.meta);
  // An inherited witness parameter was validated at the entry that set it.
  if ('witness' in parameters) {
    validateWitnessParameter(resolverContext.meta.witness);
  }

  return sourceEntry.state;
};

const getRequiredWitnessForEntry = (
  previousWitness: WitnessParameter | undefined,
  parameters: DIDLogEntry['parameters'],
  currentWitness: WitnessParameter | undefined
): WitnessParameter | undefined => {
  const explicitWitness = resolveWitnessParameter(parameters);

  // A list change takes effect only after its entry is published, so the previous list
  // governs that entry; only activation from {} uses the new (current) list immediately.
  if (hasActiveWitnessRequirement(previousWitness)) {
    return previousWitness;
  }

  if (explicitWitness !== undefined && hasActiveWitnessRequirement(currentWitness)) {
    return currentWitness;
  }

  return undefined;
};

const enforceRequiredWitnessChecks = async ({
  requiredWitnessChecks,
  options,
  did,
  logEntries,
}: {
  requiredWitnessChecks: RequiredWitnessCheck[];
  options: InternalResolutionOptions;
  did: string;
  logEntries: DIDLog;
}): Promise<void> => {
  // The witness file's URL is derived from the DID's location. A DID that
  // names none has only the proofs the caller passed.
  const proofsForDid = async () =>
    profileOf(options).hasLocation ? loadWitnessProofs(did, options) : (options.witnessProofs ?? []);
  const witnessProofs = await (options.loadWitnessProofs ?? proofsForDid)();

  const publishedVersionNumbers = new Map(logEntries.map((entry, index) => [entry.versionId, index + 1]));

  // Sort the proofs by published version number once; each check's candidates
  // are then the suffix at or above its target version.
  const indexedProofs = witnessProofs
    .map((witnessProof) => ({
      witnessProof,
      versionNumber: publishedVersionNumbers.get(witnessProof.versionId),
    }))
    .filter((entry): entry is { witnessProof: WitnessProofFileEntry; versionNumber: number } => {
      return entry.versionNumber !== undefined;
    })
    .sort((a, b) => a.versionNumber - b.versionNumber);

  const proofsAtOrAbove = (targetVersionNumber: number): WitnessProofFileEntry[] => {
    // Binary search for the first proof with versionNumber >= target.
    let low = 0;
    let high = indexedProofs.length;
    while (low < high) {
      const mid = (low + high) >> 1;
      if (indexedProofs[mid].versionNumber < targetVersionNumber) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    return indexedProofs.slice(low).map((entry) => entry.witnessProof);
  };

  // Identical (versionId, verificationMethod, proofValue) triples are verified
  // at most once across all checks; keyed by promise so concurrent checks
  // dedupe too.
  const proofVerificationCache = new Map<string, Promise<boolean>>();

  const runCheck = async (check: RequiredWitnessCheck): Promise<void> => {
    const threshold = check.witness.threshold ?? 0;
    const approvals = await countVerifiedWitnessApprovals(proofsAtOrAbove(check.targetVersionNumber), check.witness, {
      verifier: options.verifier,
      resolveVM: requireResolveVM(options),
      threshold,
      proofVerificationCache,
    });

    if (approvals < threshold) {
      throw new WitnessThresholdError(
        `Witness threshold not met for version ${check.targetVersionId}: got ${approvals}, need ${check.witness.threshold}`,
        check.targetVersionNumber
      );
    }
  };

  // Run the independent checks concurrently, but surface the earliest check's
  // failure first to preserve the sequential-first-failure error message.
  const results = await Promise.allSettled(requiredWitnessChecks.map(runCheck));
  for (const result of results) {
    if (result.status === 'rejected') {
      throw result.reason;
    }
  }
};
