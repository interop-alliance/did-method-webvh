import { createDataIntegrityProofTemplate, signDataIntegrityProof } from './cryptography.js';
import type { WitnessProofFileEntry, WitnessSigningOptions } from './interfaces.js';
import { resolveWitnessCandidateRequirement } from './method_versions/method.v1.0.resolution.js';
import { parseDidKeyDid, parseDidKeyVerificationMethod } from './utils.js';
import { defaultWebvhLogVerifier } from './verifier.js';
import { createResolveVM } from './vm-resolver.js';
import { hasActiveWitnessRequirement } from './witness.js';

/**
 * Validates a controller-proposed candidate log and signs its final entry as
 * a witness.
 *
 * The candidate must extend the trusted log by exactly one entry (or be a
 * single genesis entry when the trusted log is empty). The whole candidate is
 * resolved, so a broken hash chain, a bad controller proof, or an entry after
 * a deactivation is rejected, and the witness thresholds of every earlier
 * version are enforced against `witnessProofs`. The final entry must be
 * governed by an active witness requirement that lists the signer's did:key
 * DID. Nothing is fetched: callers supply the published witness proofs.
 *
 * This module sits above `witness.ts` (the proof primitives) and the resolver
 * because the resolver imports the primitives.
 *
 * @returns A witness proof file entry holding exactly one proof for the
 * candidate entry's `versionId`.
 */
export const signWitnessProofEntry = async (options: WitnessSigningOptions): Promise<WitnessProofFileEntry> => {
  // Runtime guard: the resolver fetches witness proofs when the option is
  // absent, which would silently fetch for an untyped caller.
  if (!Array.isArray(options.witnessProofs)) {
    throw new Error('witnessProofs is required; pass [] for an empty witness list');
  }
  if (options.candidateLog.length !== options.trustedLog.length + 1) {
    throw new Error('candidateLog must contain exactly one entry more than trustedLog');
  }
  const trustedTip = options.trustedLog.at(-1);
  if (trustedTip && options.candidateLog.at(-2)?.versionId !== trustedTip.versionId) {
    throw new Error('Candidate log does not extend the trusted log tip');
  }

  const requirement = await resolveWitnessCandidateRequirement(options.candidateLog, {
    verifier: options.verifier ?? defaultWebvhLogVerifier,
    witnessProofs: options.witnessProofs,
    resolveVM: createResolveVM(),
  });
  const witnesses = requirement?.witnesses;
  if (!hasActiveWitnessRequirement(requirement) || !witnesses) {
    throw new Error('Candidate entry is not governed by an active witness requirement');
  }

  const signerVerificationMethod = options.witnessSigner.getVerificationMethodId();
  const signerDid = parseDidKeyVerificationMethod(signerVerificationMethod).did;
  const isMember = witnesses.some((witness) => parseDidKeyDid(witness.id).did === signerDid);
  if (!isMember) {
    throw new Error(`Witness signer is not a member of the governing witness list: ${signerDid}`);
  }

  const candidateEntry = options.candidateLog[options.candidateLog.length - 1];
  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod: signerVerificationMethod,
    proofPurpose: 'assertionMethod',
  });
  const proof = await signDataIntegrityProof(
    { versionId: candidateEntry.versionId },
    proofTemplate,
    options.witnessSigner
  );
  return { versionId: candidateEntry.versionId, proof: [proof] };
};
