import {
  createDataIntegrityProofTemplate,
  prepareDataForSigning,
  resolvePublicKeyMultibase,
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
 * Whether a witness parameter requires witness proofs. Only a validated
 * parameter is passed here, so anything other than `{}` (or an absent
 * parameter) is an active requirement.
 */
export function hasActiveWitnessRequirement(witness?: WitnessParameter | null): witness is WitnessParameter {
  if (!witness?.witnesses || witness.witnesses.length === 0) {
    return false;
  }

  return (witness.threshold ?? 0) > 0;
}

/**
 * Normalizes an entry's `witness` parameter at the parse boundary: an absent
 * key returns `undefined` (inherit the prior value) and a cleared (`null`)
 * witness becomes `{}`. A malformed value (a non-integer threshold, a witness
 * list that is not an array) is left as-is for `validateWitnessParameter` to
 * reject. The returned object never aliases the entry's parameters, so
 * mutating resolution meta cannot corrupt the caller's log.
 */
export function resolveWitnessParameter(parameters: DIDLogEntry['parameters']): WitnessParameter | undefined {
  if (!('witness' in parameters)) {
    return undefined;
  }

  const witness: WitnessParameter = { ...(parameters.witness ?? {}) };
  if (Array.isArray(witness.witnesses)) {
    witness.witnesses = witness.witnesses.map((entry) => ({ ...entry }));
  }
  return witness;
}

/**
 * Normalizes `createDID` / `updateDID` witness input to the parameter that is
 * written. `null`, or an absent or empty witness list, writes `{}`, which
 * disables witnessing; a `threshold` given with no witnesses must still be an
 * integer. Any other input is validated by `validateWitnessParameter` and
 * written as `{ threshold, witnesses }`.
 */
export function toWitnessParameter(witness: WitnessParameter | null): WitnessParameter {
  const { threshold, witnesses } = (witness ?? {}) as { threshold: unknown; witnesses: unknown };
  if (witnesses === undefined || (Array.isArray(witnesses) && witnesses.length === 0)) {
    assertIntegerThreshold(threshold);
    return {};
  }
  const normalized = { threshold, witnesses } as WitnessParameter;
  validateWitnessParameter(normalized);
  return normalized;
}

const assertIntegerThreshold = (threshold: unknown): void => {
  // did:webvh v1.0 requires a JSON integer; strings and fractions are rejected rather than coerced.
  if (threshold !== undefined && !Number.isInteger(threshold)) {
    throw new Error(`Witness threshold must be an integer: ${JSON.stringify(threshold)}`);
  }
};

/**
 * Validates a witness parameter. `{}` (and an absent or `null` parameter)
 * disables witnessing. Any other value must carry a non-empty `witnesses`
 * array of distinct Ed25519 `did:key` DIDs and an integer `threshold` from 1
 * to the number of witnesses. The specification requires resolution to fail
 * on a malformed witness parameter rather than treat it as "no witnesses".
 * Keys other than `threshold` and `witnesses` are not checked.
 */
export function validateWitnessParameter(witness: WitnessParameter | null | undefined): void {
  if (!witness) {
    return;
  }
  if (typeof witness !== 'object' || Array.isArray(witness)) {
    throw new Error('Witness parameter must be a JSON object');
  }
  if (Object.keys(witness).length === 0) {
    return;
  }

  const { threshold, witnesses } = witness as { threshold: unknown; witnesses: unknown };
  assertIntegerThreshold(threshold);
  if (!Array.isArray(witnesses) || witnesses.length === 0) {
    throw new Error('Witness list must be a non-empty array');
  }
  if (threshold === undefined) {
    throw new Error('Witness threshold is required');
  }

  if ((threshold as number) < 1 || (threshold as number) > witnesses.length) {
    throw new Error('Witness threshold must be between 1 and the number of witnesses');
  }

  const ids = new Set<string>();
  for (const w of witnesses as WitnessEntry[]) {
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

    const publicKey = decodeEd25519Multikey(await resolvePublicKeyMultibase(resolveVM, proof.verificationMethod));

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
  } catch {
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
      } catch {
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
