import { documentStateIsValid, newKeysAreInNextKeys } from '../assertions.js';
import { METHOD_PROTOCOL_V1_0, PLACEHOLDER, VERIFICATION_RELATIONSHIPS } from '../constants.js';
import { createDataIntegrityProofTemplate, signDataIntegrityProof } from '../cryptography.js';
import {
  appendAlias,
  assertContextOptions,
  convertWebvhIdToWebId,
  createDIDDoc,
  enrichAlsoKnownAs,
  mergeAdditionalContext,
  replaceCreateDidPlaceholders,
  sanitizeVerificationMethods,
  validateCreateDidDocument,
} from '../did-document.js';
import type {
  CreateDIDInterface,
  DeactivateDIDInterface,
  DIDDoc,
  DIDLogEntry,
  DIDResolutionMeta,
  UpdateDIDInterface,
} from '../interfaces.js';
import { deriveHash } from '../utils/crypto.js';
import { buildVersionId, normalizeUpdateDidAddress, parseDidWebvhIdentifier, requireDidDocumentId } from '../utils.js';
import { resolveVM } from '../vm-resolver.js';
import { validateWitnessParameter } from '../witness.js';

const resolveNextDidContext = ({
  options,
  lastEntryDid,
  parsedLastEntryDid,
  portable,
}: {
  options: UpdateDIDInterface;
  lastEntryDid: string;
  parsedLastEntryDid: ReturnType<typeof parseDidWebvhIdentifier>;
  portable: boolean;
}): string => {
  const requestedAddress = options.address;
  if (!requestedAddress) {
    return lastEntryDid;
  }

  const normalizedAddress = normalizeUpdateDidAddress({
    address: requestedAddress,
    scid: parsedLastEntryDid.scid,
    paths: options.paths,
    priorPaths: parsedLastEntryDid.paths ?? [],
    context: 'updateDID path segments',
  });
  const controller = normalizedAddress.controller;

  if (controller !== lastEntryDid && !portable) {
    throw new Error('Cannot move DID: portability is disabled');
  }

  return controller;
};

const signControllerEntry = async (entry: DIDLogEntry, created: string, signer: CreateDIDInterface['signer']) => {
  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod: signer.getVerificationMethodId(),
    created,
    proofPurpose: 'assertionMethod',
  });

  return signDataIntegrityProof(entry, proofTemplate, signer);
};

const validateProposedEntry = async (
  entry: DIDLogEntry,
  updateKeys: string[],
  { verifier, selfVerify }: Pick<CreateDIDInterface, 'verifier' | 'selfVerify'>
) => {
  // Post-sign self-verification, on by default; opt out via selfVerify: false.
  if (selfVerify === false) {
    return;
  }

  const verified = await documentStateIsValid(entry, { updateKeys, verifier, resolveVM });

  if (!verified) {
    throw new Error(`version ${entry.versionId} is invalid.`);
  }
};

const finalizeNonGenesisEntry = async ({
  logEntry,
  versionNumber,
  created,
  signer,
  updateKeys,
  verifier,
  selfVerify,
}: {
  logEntry: DIDLogEntry;
  versionNumber: number;
  created: string;
  signer: CreateDIDInterface['signer'];
  updateKeys: string[];
  verifier: CreateDIDInterface['verifier'];
  selfVerify?: boolean;
}): Promise<DIDLogEntry> => {
  const logEntryHash = await deriveHash(logEntry);
  const entry = { ...logEntry, versionId: buildVersionId(versionNumber, logEntryHash) };
  entry.proof = [await signControllerEntry(entry, created, signer)];

  await validateProposedEntry(entry, updateKeys, { verifier, selfVerify });

  return entry;
};

export async function prepareGenesisEntry({
  options,
  controller,
  createdDate,
}: {
  options: CreateDIDInterface;
  controller: string;
  createdDate: string;
}): Promise<DIDLogEntry> {
  assertContextOptions(options);

  const safeVerificationMethods = sanitizeVerificationMethods(options.verificationMethods);

  let doc: DIDDoc;
  if (options.didDocument) {
    validateCreateDidDocument(options.didDocument);
    doc = structuredClone(options.didDocument);
    if (options.additionalContext !== undefined) {
      doc['@context'] = mergeAdditionalContext(doc['@context'], options.additionalContext);
    }
  } else {
    if (!safeVerificationMethods || safeVerificationMethods.length === 0) {
      throw new Error('verificationMethods must be provided when didDocument is not supplied');
    }
    doc = createDIDDoc({
      ...options,
      did: controller,
      verificationMethods: safeVerificationMethods,
    });
  }

  doc = enrichAlsoKnownAs(doc, controller, {
    alsoKnownAsWeb: options.alsoKnownAsWeb,
  });

  const initialLogEntry: DIDLogEntry = {
    versionId: PLACEHOLDER,
    versionTime: createdDate,
    parameters: {
      method: METHOD_PROTOCOL_V1_0,
      scid: PLACEHOLDER,
      updateKeys: options.updateKeys,
      portable: options.portable ?? false,
      nextKeyHashes: options.nextKeyHashes ?? [],
      watchers: options.watchers ?? [],
      witness: options.witness ?? {},
      deactivated: false,
    },
    state: doc,
  };

  const scid = await deriveHash(initialLogEntry);
  const didWithScid = controller.replaceAll(PLACEHOLDER, scid);
  // The web alias was already appended (pre-SCID-derivation, so it is part of
  // the hashed genesis entry); placeholder substitution needs no re-enrich --
  // `convertWebvhIdToWebId` strips the SCID segment, so both derivations are
  // byte-identical.
  const entry = replaceCreateDidPlaceholders(initialLogEntry, scid, didWithScid);

  const logEntryHash = await deriveHash(entry);
  entry.versionId = buildVersionId(1, logEntryHash);
  entry.proof = [await signControllerEntry(entry, createdDate, options.signer)];

  await validateProposedEntry(entry, options.updateKeys, options);

  const didId = requireDidDocumentId(entry.state.id);
  if (didId !== didWithScid) {
    throw new Error(`Created DID document id must match expected DID '${didWithScid}', got '${didId}'`);
  }

  return entry;
}

export async function prepareUpdateEntry({
  options,
  lastEntry,
  lastMeta,
  versionNumber,
  createdDate,
}: {
  options: UpdateDIDInterface;
  lastEntry: DIDLogEntry;
  lastMeta: DIDResolutionMeta;
  versionNumber: number;
  createdDate: string;
}): Promise<DIDLogEntry> {
  assertContextOptions(options);

  const lastEntryDid = requireDidDocumentId(lastEntry.state.id);
  const parsedLastEntryDid = parseDidWebvhIdentifier(lastEntryDid, 'last entry state.id');

  const watchersValue = options.watchers !== undefined ? options.watchers : lastMeta.watchers;
  const witness = options.witness?.witnesses?.length
    ? {
        witnesses: options.witness.witnesses,
        threshold: options.witness.threshold ?? 0,
      }
    : {};

  if (options.portable === true) {
    throw new Error(
      'portable: true cannot be set in an update entry; portability can only be enabled in the first entry'
    );
  }

  const params = {
    ...(options.updateKeys !== undefined || lastMeta.prerotation
      ? { updateKeys: options.updateKeys ?? lastMeta.updateKeys }
      : {}),
    ...(options.nextKeyHashes !== undefined ? { nextKeyHashes: options.nextKeyHashes } : {}),
    ...(options.portable === false ? { portable: false } : {}),
    witness,
    watchers: watchersValue ?? [],
  };

  validateWitnessParameter(params.witness);

  if (lastMeta.prerotation) {
    await newKeysAreInNextKeys(options.updateKeys ?? [], lastMeta.nextKeyHashes ?? []);
  }

  const safeVerificationMethods = sanitizeVerificationMethods(options.verificationMethods);

  // Compute controller DID id; rebuild with new address if moving, keep SCID stable.
  const controller = resolveNextDidContext({
    options,
    lastEntryDid,
    parsedLastEntryDid,
    portable: lastMeta.portable,
  });

  const normalizedUpdateDoc = createDIDDoc({
    ...options,
    did: controller,
    context: options.context || lastEntry.state['@context'],
    verificationMethods: safeVerificationMethods ?? [],
  });

  // Carry the prior DID document forward and selectively overlay only the fields
  // this update actually supplies, so a sparse updateDID() preserves prior state.
  const doc = structuredClone(lastEntry.state);
  doc['@context'] = normalizedUpdateDoc['@context'];
  doc.id = normalizedUpdateDoc.id;
  doc.controller = normalizedUpdateDoc.controller;

  if (safeVerificationMethods !== undefined) {
    doc.verificationMethod = normalizedUpdateDoc.verificationMethod;
    doc.authentication = normalizedUpdateDoc.authentication;
    doc.assertionMethod = normalizedUpdateDoc.assertionMethod;
    doc.keyAgreement = normalizedUpdateDoc.keyAgreement;
    doc.capabilityDelegation = normalizedUpdateDoc.capabilityDelegation;
    doc.capabilityInvocation = normalizedUpdateDoc.capabilityInvocation;
  }

  if (options.services !== undefined) {
    doc.service = options.services;
  }

  // Explicit relationship options overwrite the carried-forward arrays,
  // uniformly across all five declared relationships.
  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const override = options[relationship];
    if (override !== undefined) {
      doc[relationship] = override;
    }
  }

  if (options.alsoKnownAs !== undefined) {
    doc.alsoKnownAs = options.alsoKnownAs;
  }

  if (controller !== lastEntryDid) {
    doc.alsoKnownAs = appendAlias(doc.alsoKnownAs, lastEntryDid);
  }

  if (options.alsoKnownAsWeb) {
    doc.alsoKnownAs = appendAlias(doc.alsoKnownAs, convertWebvhIdToWebId(controller));
  }

  const logEntry: DIDLogEntry = {
    versionId: lastEntry.versionId,
    versionTime: createdDate,
    parameters: params,
    state: doc,
  };

  const keysToVerify = lastMeta.prerotation ? options.updateKeys : lastMeta.updateKeys;
  if (!keysToVerify) {
    throw new Error('updateKeys could not be determined for update verification');
  }

  const entry = await finalizeNonGenesisEntry({
    logEntry,
    versionNumber,
    created: createdDate,
    signer: options.signer,
    updateKeys: keysToVerify,
    verifier: options.verifier,
    selfVerify: options.selfVerify,
  });

  return entry;
}

export async function prepareDeactivationEntry({
  options,
  lastEntry,
  lastMeta,
  versionNumber,
  createdDate,
}: {
  options: DeactivateDIDInterface;
  lastEntry: DIDLogEntry;
  lastMeta: DIDResolutionMeta;
  versionNumber: number;
  createdDate: string;
}): Promise<DIDLogEntry> {
  if (lastMeta.prerotation) {
    await newKeysAreInNextKeys(options.updateKeys ?? [], lastMeta.nextKeyHashes ?? []);
  }

  const params = {
    updateKeys: options.updateKeys ?? lastMeta.updateKeys,
    // Close the rotation: a deactivated DID carries no dangling key commitment.
    nextKeyHashes: [],
    deactivated: true,
  };

  const logEntry: DIDLogEntry = {
    versionId: lastEntry.versionId,
    versionTime: createdDate,
    parameters: params,
    state: lastEntry.state,
  };

  // Under active pre-rotation the resolver verifies this entry against its own
  // updateKeys, so sign and validate with the pre-committed keys.
  const keysToVerify = lastMeta.prerotation ? options.updateKeys : lastMeta.updateKeys;
  if (!keysToVerify) {
    throw new Error('updateKeys could not be determined for deactivation verification');
  }

  const entry = await finalizeNonGenesisEntry({
    logEntry,
    versionNumber,
    created: createdDate,
    signer: options.signer,
    updateKeys: keysToVerify,
    verifier: options.verifier,
    selfVerify: options.selfVerify,
  });

  return entry;
}
