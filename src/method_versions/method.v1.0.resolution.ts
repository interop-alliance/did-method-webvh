import { documentStateIsValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions.js';
import { DEFAULT_TTL_SECONDS, METHOD_PROTOCOL_V1_0, PLACEHOLDER } from '../constants.js';
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
  parseAndValidateVersionId,
  parseDidWebvhIdentifier,
  replaceValueInObject,
  requireDidDocumentId,
} from '../utils.js';
import {
  countVerifiedWitnessApprovals,
  fetchWitnessProofs,
  hasActiveWitnessRequirement,
  resolveWitnessParameter,
  validateWitnessParameter,
} from '../witness.js';
import { applyEntryToMeta } from './method.v1.0.meta.js';

// The default VM resolver lives above this module (`vm-resolver.ts` needs full
// log resolution), so the method layer injects it via options.
const requireResolveVM = (options: ResolutionOptions): ResolveVerificationMethod => {
  if (!options.resolveVM) {
    throw new Error('resolveVM implementation is required');
  }
  return options.resolveVM;
};

/** A required-witness threshold that was not met during resolution. */
export class WitnessThresholdError extends Error {}

interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameter;
}

interface ResolutionSnapshot {
  did: string;
  doc: DIDDoc | null;
  meta: DIDResolutionMeta;
}

interface ResolverContext {
  meta: DIDResolutionMeta;
  host: string;
  previousVersionTime: Date | undefined;
  resolvedSnapshot: ResolutionSnapshot | null;
  lastValidSnapshot: ResolutionSnapshot | null;
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
  parsedStateDid: ReturnType<typeof parseDidWebvhIdentifier>;
}

export const resolveV1Log = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
): Promise<{ did: string; doc: DIDDoc | null; meta: DIDResolutionMeta }> => {
  // Stage 1: initialize resolution input and context.
  const selectorError = validateResolutionSelectors(options);
  if (selectorError) {
    throw new Error(selectorError.detail);
  }
  if (log.length === 0) {
    throw new Error(`Log identity binding check failed: no entries to process`);
  }
  const protocol = log[0]?.parameters?.method;
  if (protocol !== METHOD_PROTOCOL_V1_0) {
    throw new Error(`'${protocol}' is not a supported method version.`);
  }
  const resolverContext = createInitialResolverContext();
  const hasExplicitHistoricalSelector =
    options.versionNumber !== undefined ||
    options.versionId !== undefined ||
    options.versionTime !== undefined ||
    options.verificationMethod !== undefined;

  try {
    // Stage 2: process log entries and enforce post-loop checks.
    await processResolvedLogEntries({
      resolverContext,
      logEntries: log,
      options,
    });
  } catch (e) {
    // Stage 3: preserve a captured historical result when possible.
    const resolvedSnapshot = resolverContext.resolvedSnapshot;
    if (!resolvedSnapshot) {
      throw e;
    }

    if (resolvedSnapshot.meta && (!hasExplicitHistoricalSelector || e instanceof WitnessThresholdError)) {
      const message = e instanceof Error ? e.message : String(e);
      Object.assign(resolvedSnapshot.meta, toErrorMeta('invalidDid', message));
    }
  }

  // Stage 4: finalize fallback selection and shape the response.
  let resolvedSnapshot = resolverContext.resolvedSnapshot;

  if (!resolvedSnapshot && hasExplicitHistoricalSelector) {
    const lastValidSnapshot = resolverContext.lastValidSnapshot;
    if (!lastValidSnapshot) {
      throw new Error('DID resolution failed: No valid result available for explicit selector');
    }

    return {
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
    resolvedSnapshot = resolverContext.lastValidSnapshot;
    if (resolvedSnapshot?.meta.deactivated) {
      resolvedSnapshot = {
        ...resolvedSnapshot,
        doc: null,
      };
    }
  }

  if (!resolvedSnapshot) {
    throw new Error('DID resolution failed: No valid metadata found');
  }

  if (!resolvedSnapshot.did) {
    throw new Error('DID resolution failed: No valid identifier found');
  }

  // Deactivation is DID-global state. A historical selector keeps the
  // historical document while still reporting deactivated: true when the
  // log's final state is deactivated; non-historical resolution nulls the
  // document as before.
  if (hasExplicitHistoricalSelector) {
    if (resolverContext.meta.deactivated) {
      resolvedSnapshot = markResolvedSnapshotDeactivated({ resolvedSnapshot, resolverContext });
    }
  } else if (resolvedSnapshot.meta.deactivated) {
    resolvedSnapshot = markResolvedSnapshotDeactivated({ resolvedSnapshot, resolverContext });
    return {
      did: resolvedSnapshot.did,
      doc: null,
      meta: resolvedSnapshot.meta,
    };
  }

  if (!resolvedSnapshot.doc) {
    throw new Error('DID resolution failed: No valid document found');
  }

  return {
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
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
}): Promise<void> => {
  // Process each log entry in order and update resolution context.
  for (let entryIndex = 0; entryIndex < logEntries.length; entryIndex++) {
    const entryContext = validateAndParseLogEntry({
      entry: logEntries[entryIndex],
      expectedVersionNumber: entryIndex + 1,
      previousVersionTime: resolverContext.previousVersionTime,
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
    if (!matchesSelector && options.versionTime && options.versionTime > entryContext.currentVersionTime) {
      // The next entry's versionTime is parsed here only when a versionTime
      // selector is in play; the next iteration's strict validation is the
      // canonical parse.
      const nextEntry = logEntries[entryIndex + 1];
      matchesSelector = !nextEntry || options.versionTime < new Date(nextEntry.versionTime);
    }

    const snapshot: ResolutionSnapshot = {
      doc,
      did,
      meta: { ...resolverContext.meta },
    };
    if (matchesSelector && !resolverContext.resolvedSnapshot) {
      resolverContext.resolvedSnapshot = snapshot;
    }
    resolverContext.lastValidSnapshot = snapshot;
  }

  // Run post-iteration invariants and witness enforcement.
  if (options.requestedDid && !resolverContext.didIdMatched) {
    throw new Error(`Requested DID '${options.requestedDid}' does not match state.id in any valid log version`);
  }

  if (resolverContext.requiredWitnessChecks.length > 0) {
    await enforceRequiredWitnessChecks({
      requiredWitnessChecks: resolverContext.requiredWitnessChecks,
      options,
      did: resolverContext.lastValidSnapshot?.did ?? '',
      logEntries,
    });
  }
};

const createInitialResolverContext = (): ResolverContext => {
  return {
    meta: {
      versionId: '',
      versionTime: '',
      created: '',
      updated: '',
      deactivated: false,
      portable: false,
      ttl: DEFAULT_TTL_SECONDS,
      scid: '',
      updateKeys: [],
      nextKeyHashes: [],
      prerotation: false,
      witness: undefined,
      watchers: null,
    },
    host: '',
    previousVersionTime: undefined,
    resolvedSnapshot: null,
    lastValidSnapshot: null,
    requiredWitnessChecks: [],
    didIdMatched: false,
  };
};

const validateAndParseLogEntry = ({
  entry,
  expectedVersionNumber,
  previousVersionTime,
}: {
  entry: DIDLogEntry;
  expectedVersionNumber: number;
  previousVersionTime: Date | undefined;
}): ParsedResolutionEntryContext => {
  const { versionId, versionTime } = entry;
  const { version, versionNumber, entryHash } = parseAndValidateVersionId(versionId, expectedVersionNumber);

  if (!versionTime) {
    throw new Error(`version '${version}' is missing versionTime`);
  }

  // Check against resolver's current time for each entry per spec normative language
  const currentVersionTime = validateUtcIso8601NotInFuture(
    versionTime,
    `version '${version}' versionTime`,
    MAX_FUTURE_SKEW_MS
  );
  if (previousVersionTime && currentVersionTime.getTime() <= previousVersionTime.getTime()) {
    throw new Error(`versionTime for version '${version}' must be greater than previous entry time`);
  }

  const parsedStateDid = parseDidWebvhIdentifier(requireDidDocumentId(entry.state.id), `version '${version}' state.id`);

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
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
}): Promise<DIDDoc> => {
  const { entry: sourceEntry, parsedStateDid } = entryContext;
  const { parameters, proof } = sourceEntry;

  // applyEntryToMeta enforces the genesis invariant (non-empty scid/updateKeys)
  // via parseGenesisParameters.
  resolverContext.meta = applyEntryToMeta(sourceEntry);
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
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
}): Promise<DIDDoc> => {
  const {
    entry: sourceEntry,
    parsedVersion: { versionNumber, entryHash },
    parsedStateDid,
  } = entryContext;
  const { parameters } = sourceEntry;

  // Validate method parameter: must not be present or must equal the supported method
  if ('method' in parameters && parameters.method !== METHOD_PROTOCOL_V1_0) {
    throw new Error(
      `version '${versionNumber}' has unsupported or downgraded method '${parameters.method}'; ` +
        `expected '${METHOD_PROTOCOL_V1_0}'`
    );
  }

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
  if (recomputedHash !== entryHash) {
    throw new Error(`Hash chain broken at '${resolverContext.meta.versionId}'`);
  }

  // Signature verification
  let keys: string[];
  if (resolverContext.meta.prerotation) {
    if (!Array.isArray(parameters.updateKeys)) {
      throw new Error(`version '${versionNumber}' must declare updateKeys while pre-rotation is active`);
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
  validateWitnessParameter(resolverContext.meta.witness);

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
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
  did: string;
  logEntries: DIDLog;
}): Promise<void> => {
  const witnessProofs = options.witnessProofs ?? (await fetchWitnessProofs(did));

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
    const threshold = Number(check.witness.threshold ?? 0);
    const approvals = await countVerifiedWitnessApprovals(proofsAtOrAbove(check.targetVersionNumber), check.witness, {
      verifier: options.verifier,
      resolveVM: requireResolveVM(options),
      threshold,
      proofVerificationCache,
    });

    if (approvals < threshold) {
      throw new WitnessThresholdError(
        `Witness threshold not met for version ${check.targetVersionId}: got ${approvals}, need ${check.witness.threshold}`
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
