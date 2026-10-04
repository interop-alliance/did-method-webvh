import { assertValidNextKeyHashes, documentStateIsValid, newKeysAreInNextKeys } from '../assertions.js';
import { DID_PLACEHOLDER, METHOD_PROTOCOL_V1_0, PLACEHOLDER, VERIFICATION_RELATIONSHIPS } from '../constants.js';
import { createDataIntegrityProofTemplate, signDataIntegrityProof } from '../cryptography.js';
import {
  appendAlias,
  assertContextOptions,
  assertNoPrivateKeyMaterial,
  convertWebvhIdToWebId,
  createDIDDoc,
  enrichAlsoKnownAs,
  prepareAuthoredDocument,
  replaceCreateDidPlaceholders,
  requireAuthoredDocumentId,
  rewriteSelfReferences,
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
import { replaceValueInObject } from '../utils/object.js';
import { buildVersionId, normalizeUpdateDidAddress, parseDidWebvhIdentifier, requireDidDocumentId } from '../utils.js';
import { resolveVM } from '../vm-resolver.js';
import { validateWitnessParameter } from '../witness.js';

/**
 * The document-shaping options that replace part of a document the caller has
 * already authored in full. Combining any of them with `didDocument` is a
 * caller bug, in `createDID` as much as in `updateDID`. The two append-style
 * options are deliberately absent: `additionalContext` appends to whatever
 * `@context` the authored document carries, and `alsoKnownAsWeb` appends the
 * parallel `did:web` alias, so both compose with an authored document.
 */
const DOC_REPLACEMENT_OPTIONS = [
  'verificationMethods',
  'services',
  'alsoKnownAs',
  'context',
  ...VERIFICATION_RELATIONSHIPS,
] as const satisfies readonly (keyof CreateDIDInterface & keyof UpdateDIDInterface)[];

/**
 * The `updateDID` options that overlay fields onto the carried-forward DID
 * document. Supplying any of them selects overlay mode; supplying none (and no
 * `didDocument`) leaves the prior document untouched.
 */
const DOC_OVERLAY_OPTIONS = [
  ...DOC_REPLACEMENT_OPTIONS,
  'additionalContext',
] as const satisfies readonly (keyof UpdateDIDInterface)[];

/**
 * Refuses an authored `didDocument` combined with any option that would
 * overwrite part of it.
 */
function assertNoAuthoredDocumentOverlay(options: CreateDIDInterface | UpdateDIDInterface): void {
  if (!options.didDocument) {
    return;
  }

  const supplied = DOC_REPLACEMENT_OPTIONS.filter((name) => options[name] !== undefined);
  if (supplied.length > 0) {
    throw new Error(`didDocument replaces the whole document and cannot be combined with ${supplied.join(', ')}`);
  }
}

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
  assertNoAuthoredDocumentOverlay(options);

  const { verificationMethods } = options;
  assertNoPrivateKeyMaterial(verificationMethods, 'verificationMethods');

  let doc: DIDDoc;
  if (options.didDocument) {
    validateCreateDidDocument(options.didDocument);
    doc = prepareAuthoredDocument(options.didDocument, options.additionalContext);
  } else {
    if (!verificationMethods || verificationMethods.length === 0) {
      throw new Error('verificationMethods must be provided when didDocument is not supplied');
    }
    doc = createDIDDoc({
      ...options,
      did: controller,
      verificationMethods,
    });
  }

  // `{DID}` is substituted before SCID derivation, so the hashed genesis
  // preimage carries `did:webvh:{SCID}:<host>` rather than the literal `{DID}`
  // token. Only `{SCID}` is a spec construct; `{DID}` is a convenience this
  // library adds, and leaving it in the preimage would make the SCID depend on
  // a token no other implementation knows. This covers a `{DID}` written
  // anywhere in the document -- an authored one, or a `services` /
  // `alsoKnownAs` entry passed alongside `verificationMethods`.
  doc = replaceValueInObject(doc, DID_PLACEHOLDER, controller);

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
      nextKeyHashes: assertValidNextKeyHashes(options.nextKeyHashes ?? []),
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
    ...(options.nextKeyHashes !== undefined ? { nextKeyHashes: assertValidNextKeyHashes(options.nextKeyHashes) } : {}),
    ...(options.portable === false ? { portable: false } : {}),
    witness,
    watchers: watchersValue ?? [],
  };

  validateWitnessParameter(params.witness);

  if (lastMeta.prerotation) {
    await newKeysAreInNextKeys(options.updateKeys ?? [], lastMeta.nextKeyHashes ?? []);
  }

  const { verificationMethods } = options;
  assertNoPrivateKeyMaterial(verificationMethods, 'verificationMethods');

  assertNoAuthoredDocumentOverlay(options);

  // Compute controller DID id; rebuild with new address if moving, keep SCID stable.
  const controller = resolveNextDidContext({
    options,
    lastEntryDid,
    parsedLastEntryDid,
    portable: lastMeta.portable,
  });

  let doc: DIDDoc;
  if (options.didDocument) {
    // Authored mode: the supplied document is the complete next state. Only
    // the append-style options touch it -- `additionalContext` here, and the
    // `did:web` alias below.
    doc = prepareAuthoredDocument(options.didDocument, options.additionalContext);

    // The authored document has to name itself: either the DID it is written
    // for, or -- on a portable move -- the DID it is moving from, since the
    // caller need not have derived the new identifier yet. The move branch
    // below rewrites it to `controller` either way. Without this check an
    // authored document naming a third DID would be hashed and signed, then
    // silently overwritten.
    const authoredId = requireAuthoredDocumentId(doc);
    if (authoredId !== controller && authoredId !== lastEntryDid) {
      throw new Error(`Updated DID document id must match expected DID '${controller}', got '${authoredId}'`);
    }
  } else if (DOC_OVERLAY_OPTIONS.some((name) => options[name] !== undefined)) {
    // Overlay mode: carry the prior DID document forward and selectively
    // overlay only the fields this update actually supplies.
    const normalizedUpdateDoc = createDIDDoc({
      ...options,
      did: controller,
      context: options.context || lastEntry.state['@context'],
      verificationMethods: verificationMethods ?? [],
    });

    doc = structuredClone(lastEntry.state);
    doc['@context'] = normalizedUpdateDoc['@context'];
    doc.id = normalizedUpdateDoc.id;

    if (verificationMethods !== undefined) {
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
  } else {
    // Parameters-only update: the prior document passes through untouched.
    doc = structuredClone(lastEntry.state);
  }

  if (controller !== lastEntryDid) {
    // A portable move relocates the document, so any reference it makes to its
    // own former identifier has to follow it.
    doc.id = controller;
    doc = rewriteSelfReferences(doc, lastEntryDid, controller);
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
