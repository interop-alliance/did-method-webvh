import { documentStateIsValid, hashChainIsValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions.js';
import { METHOD_PARAMETER_KEYS, METHOD_PROTOCOL_V1_0, PLACEHOLDER } from '../constants.js';
import { findVerificationMethod } from '../did-document.js';
import type {
  DIDDoc,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  ResolutionOptions,
  WitnessParameterResolution,
  WitnessProofFileEntry,
} from '../interfaces.js';
import { toErrorMeta } from '../resolver-result.js';
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
  normalizeWitnessThreshold,
  resolveWitnessParameter,
  validateWitnessParameter,
} from '../witness.js';

const hasOwn = <K extends PropertyKey>(obj: object, key: K): obj is Record<K, unknown> => Object.hasOwn(obj, key);

interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameterResolution;
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
  did: string;
  doc: DIDDoc | null;
  resolvedSnapshot: ResolutionSnapshot | null;
  lastValidSnapshot: ResolutionSnapshot | null;
  requiredWitnessChecks: RequiredWitnessCheck[];
  didIdMatchCount: number;
  witnessThresholdFailure: boolean;
}

interface ParsedResolutionEntryContext {
  entry: DIDLogEntry;
  parsedVersion: {
    versionId: string;
    version: string;
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
  if (options.verificationMethod && (options.versionNumber || options.versionId)) {
    throw new Error('Cannot specify both verificationMethod and version number/id');
  }
  const logEntries = log.map((l) => structuredClone(l));
  if (logEntries.length === 0) {
    throw new Error(`Log identity binding check failed: no entries to process`);
  }
  const protocol = logEntries[0]?.parameters?.method;
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
      logEntries,
      options,
    });
  } catch (e) {
    // Stage 3: preserve a captured historical result when possible.
    const resolvedSnapshot = resolverContext.resolvedSnapshot;
    if (!resolvedSnapshot) {
      throw e;
    }

    if (resolvedSnapshot.meta && (!hasExplicitHistoricalSelector || resolverContext.witnessThresholdFailure)) {
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

  if (!resolvedSnapshot?.meta) {
    throw new Error('DID resolution failed: No valid metadata found');
  }

  if (!resolvedSnapshot.did) {
    throw new Error('DID resolution failed: No valid identifier found');
  }

  if (resolvedSnapshot.meta.deactivated && !hasExplicitHistoricalSelector) {
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
    doc: resolvedSnapshot.doc,
    meta: resolvedSnapshot.meta,
  };
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
      entry: { versionTime, parameters },
      parsedVersion: { versionId, version, versionNumber },
    } = entryContext;

    const previousWitness = resolverContext.meta.witness ? structuredClone(resolverContext.meta.witness) : undefined;
    resolverContext.meta.versionId = versionId;
    resolverContext.previousVersionTime = entryContext.currentVersionTime;
    resolverContext.meta.updated = versionTime;

    const resolvedEntryDoc =
      version === '1'
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

    resolverContext.doc = structuredClone(resolvedEntryDoc) as DIDDoc;
    resolverContext.did = requireDidDocumentId(resolverContext.doc.id);

    if (options.requestedDid && resolverContext.did === options.requestedDid) {
      resolverContext.didIdMatchCount++;
    }

    // Latch the first entry matching the requested selector as the resolved result.
    let matchesSelector =
      (!!options.verificationMethod && !!findVerificationMethod(resolverContext.doc, options.verificationMethod)) ||
      options.versionNumber === versionNumber ||
      options.versionId === resolverContext.meta.versionId;
    if (!matchesSelector && options.versionTime && options.versionTime > new Date(resolverContext.meta.updated)) {
      const nextEntry = logEntries[entryIndex + 1];
      matchesSelector = !nextEntry || options.versionTime < new Date(nextEntry.versionTime);
    }
    if (matchesSelector && !resolverContext.resolvedSnapshot) {
      resolverContext.resolvedSnapshot = {
        doc: structuredClone(resolverContext.doc),
        did: resolverContext.did,
        meta: { ...resolverContext.meta },
      };
    }

    resolverContext.lastValidSnapshot = {
      doc: structuredClone(resolverContext.doc),
      did: resolverContext.did,
      meta: { ...resolverContext.meta },
    };
  }

  // Run post-iteration invariants and witness enforcement.
  await finalizeResolutionChecks({
    resolverContext,
    options,
    logEntries,
  });
};

const createInitialResolverContext = (): ResolverContext => {
  return {
    meta: {
      versionId: '',
      created: '',
      updated: '',
      deactivated: false,
      portable: false,
      scid: '',
      updateKeys: [],
      nextKeyHashes: [],
      prerotation: false,
      witness: undefined,
      watchers: null,
    },
    host: '',
    previousVersionTime: undefined,
    did: '',
    doc: null,
    resolvedSnapshot: null,
    lastValidSnapshot: null,
    requiredWitnessChecks: [],
    didIdMatchCount: 0,
    witnessThresholdFailure: false,
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
      versionId,
      version,
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
  const { versionTime, parameters, proof } = sourceEntry;

  resolverContext.meta.created = versionTime;
  resolverContext.host = parsedStateDid.locationKey;
  resolverContext.meta.scid = parameters.scid as string;
  if (options.scid && options.scid !== resolverContext.meta.scid) {
    throw new Error(`SCID in DID '${options.scid}' does not match SCID in log '${resolverContext.meta.scid}'`);
  }
  resolverContext.meta.portable = parameters.portable ?? resolverContext.meta.portable;
  resolverContext.meta.updateKeys = parameters.updateKeys as string[];
  resolverContext.meta.nextKeyHashes = parameters.nextKeyHashes || [];
  resolverContext.meta.prerotation = resolverContext.meta.nextKeyHashes.length > 0;
  resolverContext.meta.witness = parameters.witness || resolverContext.meta.witness;
  resolverContext.meta.watchers = parameters.watchers ?? null;

  // Optimized: Use efficient object manipulation instead of JSON stringify/parse
  const logEntry = {
    versionId: PLACEHOLDER,
    versionTime: resolverContext.meta.created,
    parameters: replaceValueInObject(parameters, resolverContext.meta.scid, PLACEHOLDER),
    state: replaceValueInObject(sourceEntry.state, resolverContext.meta.scid, PLACEHOLDER),
  };

  const logEntryHash = await deriveHash(logEntry);
  resolverContext.meta.previousLogEntryHash = logEntryHash;
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
    resolverContext.meta.updateKeys,
    resolverContext.meta.witness,
    false,
    options.verifier
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
    parsedVersion: { version, entryHash },
    parsedStateDid,
  } = entryContext;
  const { parameters } = sourceEntry;

  // Validate method parameter: must not be present or must equal the supported method
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.method)) {
    const entryMethod = parameters.method as string;
    if (entryMethod !== METHOD_PROTOCOL_V1_0) {
      throw new Error(
        `version '${version}' has unsupported or downgraded method '${entryMethod}'; ` +
          `expected '${METHOD_PROTOCOL_V1_0}'`
      );
    }
  }

  // scid MUST NOT appear in later entries
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.scid)) {
    throw new Error(`version '${version}' must not contain SCID parameter`);
  }

  // portable: true cannot be introduced after the first entry -- it can only remain
  // true if it was already enabled in the first entry
  if (parameters.portable === true && !resolverContext.meta.portable) {
    throw new Error(
      `version '${version}' cannot set portable: true; portability can only be enabled in the first entry`
    );
  }

  // Setting portable: false in a later entry permanently locks portability off
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.portable) && parameters.portable === false) {
    resolverContext.meta.portable = false;
  }

  if (parsedStateDid.scid !== resolverContext.meta.scid) {
    throw new Error(
      `SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${resolverContext.meta.scid}'`
    );
  }

  const newLocation = parsedStateDid.locationKey;
  if (!resolverContext.meta.portable && newLocation !== resolverContext.host) {
    throw new Error('Cannot move DID: portability is disabled');
  } else if (newLocation !== resolverContext.host) {
    resolverContext.host = newLocation;
  }

  // Hash chain
  const { proof: _proof, ...entryWithoutProof } = logEntries[entryIndex];
  const recomputedHash = await deriveHash({ ...entryWithoutProof, versionId: logEntries[entryIndex - 1].versionId });
  if (!hashChainIsValid(recomputedHash, entryHash)) {
    throw new Error(`Hash chain broken at '${resolverContext.meta.versionId}'`);
  }

  // Signature verification
  const keys = resolverContext.meta.prerotation ? (parameters.updateKeys as string[]) : resolverContext.meta.updateKeys;
  const verified = await documentStateIsValid(
    logEntries[entryIndex],
    keys,
    resolverContext.meta.witness,
    false,
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${resolverContext.meta.versionId} failed verification of the proof.`);
  }

  if (resolverContext.meta.prerotation) {
    await newKeysAreInNextKeys(parameters.updateKeys ?? [], resolverContext.meta.nextKeyHashes ?? []);
  }

  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.updateKeys)) {
    resolverContext.meta.updateKeys = parameters.updateKeys ?? [];
  }
  if (parameters.deactivated === true) {
    resolverContext.meta.deactivated = true;
  }
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.nextKeyHashes)) {
    resolverContext.meta.nextKeyHashes = parameters.nextKeyHashes ?? [];
    resolverContext.meta.prerotation = resolverContext.meta.nextKeyHashes.length > 0;
  }
  const normalizedWitness = resolveWitnessParameter(parameters);

  if (normalizedWitness !== undefined) {
    resolverContext.meta.witness = normalizedWitness;
  }
  if (resolverContext.meta.witness?.witnesses?.length) {
    validateWitnessParameter(resolverContext.meta.witness);
  }
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.watchers)) {
    resolverContext.meta.watchers = parameters.watchers ?? null;
  }

  return sourceEntry.state;
};

const getRequiredWitnessForEntry = (
  previousWitness: WitnessParameterResolution | undefined,
  parameters: DIDLogEntry['parameters'],
  currentWitness: WitnessParameterResolution | undefined
): WitnessParameterResolution | undefined => {
  const explicitWitness = resolveWitnessParameter(parameters);

  // A list change takes effect only after its entry is published, so the previous list
  // governs that entry; only activation from {} uses the new (current) list immediately.
  if (hasActiveWitnessRequirement(previousWitness)) {
    return structuredClone(previousWitness);
  }

  if (explicitWitness !== undefined && hasActiveWitnessRequirement(currentWitness)) {
    return structuredClone(currentWitness);
  }

  return undefined;
};

const finalizeResolutionChecks = async ({
  resolverContext,
  options,
  logEntries,
}: {
  resolverContext: ResolverContext;
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
  logEntries: DIDLog;
}): Promise<void> => {
  if (options.requestedDid && resolverContext.didIdMatchCount === 0) {
    throw new Error(`Requested DID '${options.requestedDid}' does not match state.id in any valid log version`);
  }

  if (resolverContext.requiredWitnessChecks.length > 0) {
    await enforceRequiredWitnessChecks({
      requiredWitnessChecks: resolverContext.requiredWitnessChecks,
      options,
      did: resolverContext.did,
      logEntries,
      onThresholdFailure: () => {
        resolverContext.witnessThresholdFailure = true;
      },
    });
  }
};

const enforceRequiredWitnessChecks = async ({
  requiredWitnessChecks,
  options,
  did,
  logEntries,
  onThresholdFailure,
}: {
  requiredWitnessChecks: RequiredWitnessCheck[];
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
  did: string;
  logEntries: DIDLog;
  onThresholdFailure: () => void;
}): Promise<void> => {
  if (!options.witnessProofs) {
    options.witnessProofs = await fetchWitnessProofs(did);
  }

  const publishedVersionNumbers = new Map(logEntries.map((entry, index) => [entry.versionId, index + 1]));

  for (const check of requiredWitnessChecks) {
    const candidateProofs = (options.witnessProofs ?? []).filter((witnessProof) => {
      const proofVersionNumber = publishedVersionNumbers.get(witnessProof.versionId);
      return proofVersionNumber !== undefined && proofVersionNumber >= check.targetVersionNumber;
    });

    const approvals = await countVerifiedWitnessApprovals(
      logEntries[check.targetVersionNumber - 1],
      candidateProofs,
      check.witness,
      options.verifier
    );
    const threshold = normalizeWitnessThreshold(check.witness.threshold);

    if (approvals < threshold) {
      onThresholdFailure();
      throw new Error(
        `Witness threshold not met for version ${check.targetVersionId}: got ${approvals}, need ${check.witness.threshold}`
      );
    }
  }
};
