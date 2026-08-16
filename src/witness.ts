import {
  createDataIntegrityProofTemplate,
  prepareDataForSigning,
  signDataIntegrityProof,
  validateWebvhProofShape,
} from './cryptography.js';
import type {
  DataIntegrityProof,
  DataIntegrityProofTemplate,
  DIDLogEntry,
  ResolveVerificationMethod,
  Signer,
  Verifier,
  WitnessEntry,
  WitnessParameter,
  WitnessProofFileEntry,
  WitnessSigningOptions,
  WitnessSigningResult,
} from './interfaces.js';
import { createDate } from './utils/iso8601-datetime.js';
import { decodeEd25519Multikey, decodeMultikey, MultikeyCodec, multibaseDecode } from './utils/multiformats.js';
import { fetchWitnessProofs, parseDidKeyDid, parseDidKeyVerificationMethod } from './utils.js';

/**
 * Creates a single witness DataIntegrityProof for one `versionId`.
 *
 * @param signer Proof signer callback.
 * @param versionId Target DID log version id.
 * @param verificationMethod Witness verification method DID URL.
 * @param created Optional proof creation time in ISO format.
 * @returns A complete DataIntegrityProof for did-witness processing.
 */
export async function createWitnessProof(
  signer: (
    doc: { versionId: string },
    proofTemplate?: DataIntegrityProofTemplate
  ) => Promise<{ proof: Partial<DataIntegrityProof> }>,
  versionId: string,
  verificationMethod: string,
  created: string = createDate()
): Promise<DataIntegrityProof> {
  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod,
    created,
    proofPurpose: 'assertionMethod',
  });

  const adaptedSigner: Signer<{ versionId: string }> = {
    getVerificationMethodId: () => verificationMethod,
    sign: async ({ document, proof }): Promise<{ proofValue: string }> => {
      const signedData = await signer(document, proof);
      // Only `proofValue` is taken from the signer; the rest of the proof comes
      // from the template. Optional chaining keeps a malformed signer output
      // (no proof at all) reported as the descriptive error below.
      const proofValue = signedData?.proof?.proofValue;
      if (!proofValue) {
        throw new Error('Witness proof is missing proofValue');
      }
      return { proofValue };
    },
  };

  return signDataIntegrityProof({ versionId }, proofTemplate, adaptedSigner);
}

/**
 * Signs one did-witness proof entry for a single target `versionId`.
 *
 * The signer map is keyed by witness DID (`did:key:...`).
 *
 * @param options Witness signing options for one target version.
 * @returns A witness proof file entry for the target version.
 */
export async function signWitnessProofEntry(options: WitnessSigningOptions): Promise<WitnessSigningResult> {
  if (!options.versionId) {
    throw new Error('versionId is required');
  }

  if (options.witnesses.length === 0) {
    throw new Error('Witness list cannot be empty');
  }

  const proofs = await Promise.all(
    options.witnesses.map(async (witness) => {
      const { did } = parseDidKeyDid(witness.id);
      const signer = options.witnessSignersByDid[did];

      if (!signer) {
        throw new Error(`Missing witness signer for ${did}`);
      }

      const verificationMethod = signer.getVerificationMethodId();
      const parsedVerificationMethod = parseDidKeyVerificationMethod(verificationMethod);

      if (parsedVerificationMethod.did !== did) {
        throw new Error(`Witness signer verificationMethod DID does not match witness id: ${did}`);
      }

      const proofTemplate = createDataIntegrityProofTemplate({
        verificationMethod,
        created: options.created,
        proofPurpose: 'assertionMethod',
      });

      return signDataIntegrityProof({ versionId: options.versionId }, proofTemplate, signer);
    })
  );

  return {
    versionId: options.versionId,
    proof: proofs,
  };
}

/**
 * Signs did-witness proof entries for multiple target `versionId`s.
 *
 * @param versionIds Target DID log version ids.
 * @param witnesses Witness DID entries used to sign.
 * @param witnessSignersByDid Signer map keyed by witness did:key DID.
 * @param created Optional proof creation time in ISO format.
 * @returns A witness proof file entry per version id.
 */
export async function signWitnessProofEntries(
  versionIds: string[],
  witnesses: WitnessEntry[],
  witnessSignersByDid: Record<string, Signer>,
  created?: string
): Promise<WitnessSigningResult[]> {
  return Promise.all(
    versionIds.map((versionId) =>
      signWitnessProofEntry({
        versionId,
        witnesses,
        witnessSignersByDid,
        created,
      })
    )
  );
}

export function hasActiveWitnessRequirement(witness?: WitnessParameter | null): witness is WitnessParameter {
  if (!witness?.witnesses || witness.witnesses.length === 0) {
    return false;
  }

  return (witness.threshold ?? 0) > 0;
}

/**
 * Normalizes an entry's `witness` parameter at the parse boundary: an absent
 * key returns `undefined` (inherit the prior value), a cleared (`null`)
 * witness becomes `{}`, and a wire-format string `threshold` is coerced to a
 * number so every downstream comparison works on numbers. The legacy v0.5
 * top-level `witnesses`/`witnessThreshold` shape is rejected outright --
 * ignoring it would silently resolve a previously witness-enforced log with
 * no witness requirement. The returned object never aliases the entry's
 * parameters, so mutating resolution meta cannot corrupt the caller's log.
 */
export function resolveWitnessParameter(parameters: DIDLogEntry['parameters']): WitnessParameter | undefined {
  if ('witnesses' in parameters || 'witnessThreshold' in parameters) {
    throw new Error(
      "Legacy 'witnesses'/'witnessThreshold' parameters are not supported; declare a 'witness' parameter"
    );
  }

  if (!('witness' in parameters)) {
    return undefined;
  }

  const witness: WitnessParameter = { ...(parameters.witness ?? {}) };
  if (witness.witnesses) {
    witness.witnesses = witness.witnesses.map((entry) => ({ ...entry }));
  }
  if (witness.threshold !== undefined) {
    witness.threshold = parseInt(String(witness.threshold), 10);
  }
  return witness;
}

/**
 * Validates a non-empty witness parameter; no-ops when the parameter is
 * absent or carries an empty witness list (an inactive requirement).
 */
export function validateWitnessParameter(witness: WitnessParameter | null | undefined): void {
  if (!witness?.witnesses || !Array.isArray(witness.witnesses) || witness.witnesses.length === 0) {
    return;
  }

  const normalizedThreshold = parseInt(String(witness.threshold ?? 0), 10);

  if (!witness.threshold || normalizedThreshold < 1 || normalizedThreshold > witness.witnesses.length) {
    throw new Error('Witness threshold must be between 1 and the number of witnesses');
  }

  const ids = new Set<string>();
  for (const w of witness.witnesses) {
    let parsedDid: ReturnType<typeof parseDidKeyDid>;
    try {
      parsedDid = parseDidKeyDid(w.id);
    } catch {
      throw new Error('Witness DIDs must be did:key format');
    }

    // did:webvh v1.0 requires witness keys to be Ed25519 multikeys.
    try {
      decodeMultikey({ multikey: parsedDid.keyMultibase, expectedCodec: MultikeyCodec.ED25519_PUB });
    } catch (error) {
      throw new Error(`Witness DID key type must be Ed25519 (multicodec 0xed01): ${w.id}`, { cause: error });
    }

    if (ids.has(parsedDid.did)) {
      throw new Error(`Duplicate witness id: ${w.id}`);
    }
    ids.add(parsedDid.did);
  }
}

const verifyWitnessProofSignature = async (
  proofSet: WitnessProofFileEntry,
  proof: DataIntegrityProof,
  verifier: Verifier,
  resolveVM: ResolveVerificationMethod
): Promise<boolean> => {
  try {
    validateWebvhProofShape(proof, (field) => {
      if (field === 'type') return 'Invalid witness proof type';
      if (field === 'proofPurpose') return 'Invalid witness proof purpose';
      return 'Invalid witness proof cryptosuite';
    });

    const vm = await resolveVM(proof.verificationMethod);
    if (!vm?.publicKeyMultibase) {
      throw new Error(`Verification Method ${proof.verificationMethod} not found`);
    }

    const publicKey = decodeEd25519Multikey(vm.publicKeyMultibase);

    const { proofValue, ...proofWithoutValue } = proof;

    // Verify against the proof entry's own versionId (what the witness signed); a
    // later proof cumulatively approves earlier entries.
    const input = await prepareDataForSigning({ versionId: proofSet.versionId }, proofWithoutValue);
    const signature = multibaseDecode(proofValue).bytes;

    const verified = await verifier.verify(signature, input, publicKey);

    if (!verified) {
      throw new Error('Invalid witness proof signature');
    }
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(
      `Ignoring invalid witness proof for version ${proofSet.versionId} ` +
        `(verificationMethod: ${proof.verificationMethod}): ${message}`
    );
    return false;
  }
};

export async function countVerifiedWitnessApprovals(
  witnessProofs: WitnessProofFileEntry[],
  currentWitness: WitnessParameter,
  {
    verifier,
    resolveVM,
    threshold,
    proofVerificationCache,
  }: {
    verifier?: Verifier;
    /** Injected by the method layer; the default lives in `vm-resolver.ts`. */
    resolveVM: ResolveVerificationMethod;
    /** When set, counting stops as soon as this many approvals are found. */
    threshold?: number;
    /**
     * Memo of signature verifications keyed by
     * `versionId|verificationMethod|proofValue`, shared across the
     * required-witness checks of one resolution so an identical proof is
     * verified at most once. Keyed by promise so concurrent checks dedupe too.
     */
    proofVerificationCache?: Map<string, Promise<boolean>>;
  }
): Promise<number> {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }

  let approvals = 0;
  const processedWitnesses = new Set<string>();
  const witnessesByDid = new Map(
    (currentWitness.witnesses ?? []).map((witness) => {
      const parsedDid = parseDidKeyDid(witness.id);
      return [parsedDid.did, witness];
    })
  );

  for (const proofSet of witnessProofs) {
    for (const proof of proofSet.proof) {
      let witness: WitnessEntry | undefined;
      try {
        const parsedVerificationMethod = parseDidKeyVerificationMethod(proof.verificationMethod);
        witness = witnessesByDid.get(parsedVerificationMethod.did);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.warn(
          `Ignoring invalid witness proof for version ${proofSet.versionId} ` +
            `(verificationMethod: ${proof.verificationMethod}): ${message}`
        );
        continue;
      }
      if (!witness || processedWitnesses.has(witness.id)) {
        continue;
      }

      let verified: boolean;
      if (proofVerificationCache) {
        // The signature binds the proof options (including verificationMethod),
        // so the key must carry it: the same proofValue under a different
        // verificationMethod is a distinct proof that must be verified against
        // that witness's own key, never served from the memo.
        const cacheKey = `${proofSet.versionId}|${proof.verificationMethod}|${proof.proofValue}`;
        let pending = proofVerificationCache.get(cacheKey);
        if (!pending) {
          pending = verifyWitnessProofSignature(proofSet, proof, verifier, resolveVM);
          proofVerificationCache.set(cacheKey, pending);
        }
        verified = await pending;
      } else {
        verified = await verifyWitnessProofSignature(proofSet, proof, verifier, resolveVM);
      }

      if (verified) {
        approvals++;
        processedWitnesses.add(witness.id);
        if (threshold !== undefined && approvals >= threshold) {
          return approvals;
        }
      }
    }
  }

  return approvals;
}

export { fetchWitnessProofs };
