import type { DataIntegrityProof, DIDLogEntry, Verifier, WitnessParameterResolution } from './interfaces.js';
import { concatBuffers } from './utils/buffer.js';
import { canonicalizeStrict } from './utils/canonicalize.js';
import { createHash, createSCID, deriveNextKeyHash } from './utils/crypto.js';
import {
  decodeBase58Btc,
  decodeMultihash,
  isEd25519Multikey,
  MultihashAlgorithm,
  multibaseDecode,
} from './utils/multiformats.js';
import { parseDidKeyVerificationMethod, resolveVM } from './utils.js';
import { validateWitnessParameter } from './witness.js';

const isKeyAuthorized = (verificationMethod: string, updateKeys: string[]): boolean => {
  const parsedVerificationMethod = parseDidKeyVerificationMethod(verificationMethod);

  return updateKeys.some((updateKey) => {
    return updateKey === parsedVerificationMethod.keyMultibase;
  });
};

/**
 * Generic log-entry proof verification: the format-independent half of
 * `documentStateIsValid`, with the two method-specific decisions injected --
 * `authorize` (which signing keys may extend the log; throws to refuse) and
 * `resolveVM` (how a proof's `verificationMethod` id resolves to key
 * material). The fixed proof shape (`DataIntegrityProof` / `assertionMethod` /
 * `eddsa-jcs-2022`, Ed25519 multikey) is part of the kernel and is not
 * parameterized. Non-DID log profiles supply their own authorization rule
 * (e.g. verification against an externally verified controller document);
 * the did:webvh method is one caller, via `documentStateIsValid`.
 */
export const verifyEntryProofs = async (
  entry: { proof?: DataIntegrityProof | DataIntegrityProof[] },
  {
    verifier,
    authorize,
    resolveVM,
  }: {
    verifier?: Verifier;
    authorize: (proof: DataIntegrityProof) => void | Promise<void>;
    resolveVM: (verificationMethod: string) => Promise<{ publicKeyMultibase?: string } | null | undefined>;
  }
) => {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }

  let { proof: proofs, ...rest } = entry;
  if (!proofs) {
    throw new Error('Missing proof in DID log entry');
  }
  if (!Array.isArray(proofs)) {
    proofs = [proofs];
  }

  for (let i = 0; i < proofs.length; i++) {
    const proof = proofs[i];

    await authorize(proof);

    if (proof.type !== 'DataIntegrityProof') {
      throw new Error(`Unknown proof type ${proof.type}`);
    }
    if (proof.proofPurpose !== 'assertionMethod') {
      throw new Error(
        `Invalid proof purpose '${proof.proofPurpose}' for DID log entry proof. Expected 'assertionMethod'.`
      );
    }
    if (proof.cryptosuite !== 'eddsa-jcs-2022') {
      throw new Error(`Unknown cryptosuite ${proof.cryptosuite}`);
    }

    const vm = await resolveVM(proof.verificationMethod);
    if (!vm?.publicKeyMultibase) {
      throw new Error(`Verification Method ${proof.verificationMethod} not found`);
    }

    const publicKey = multibaseDecode(vm.publicKeyMultibase).bytes;
    if (!isEd25519Multikey(publicKey)) {
      throw new Error(`multiKey doesn't include ed25519 header (0xed01)`);
    }

    const { proofValue, ...restProof } = proof;
    const signature = multibaseDecode(proofValue).bytes;
    const dataHash = await createHash(canonicalizeStrict(rest));
    const proofHash = await createHash(canonicalizeStrict(restProof));
    const input = concatBuffers(proofHash, dataHash);

    const verified = await verifier.verify(signature, input, publicKey.slice(2));

    if (!verified) {
      throw new Error(`Proof ${i} failed verification (proofValue: ${proofValue})`);
    }
  }
  return true;
};

export const documentStateIsValid = async (
  doc: DIDLogEntry,
  updateKeys: string[],
  witness: WitnessParameterResolution | undefined | null,
  skipWitnessVerification?: boolean,
  verifier?: Verifier
) => {
  // Repeated from verifyEntryProofs so the failure precedence (verifier, then
  // proof presence, then witness-parameter validity) matches the pre-extraction
  // behavior of this function.
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }
  if (!doc.proof) {
    throw new Error('Missing proof in DID log entry');
  }

  if (witness?.witnesses && witness.witnesses.length > 0) {
    if (!skipWitnessVerification) {
      validateWitnessParameter(witness);
    }
  }

  return verifyEntryProofs(doc, {
    verifier,
    authorize: (proof) => {
      if (!proof.verificationMethod.startsWith('did:key:')) {
        throw new Error(`Unsupported verification method for DID log entry authorization: ${proof.verificationMethod}`);
      }

      if (!isKeyAuthorized(proof.verificationMethod, updateKeys)) {
        throw new Error(`Key ${proof.verificationMethod} is not authorized to update.`);
      }
    },
    resolveVM: (verificationMethod) => resolveVM(verificationMethod),
  });
};

export const hashChainIsValid = (derivedHash: string, logEntryHash: string) => {
  return derivedHash === logEntryHash;
};

export const newKeysAreInNextKeys = async (updateKeys: string[], previousNextKeyHashes: string[]) => {
  if (previousNextKeyHashes.length > 0) {
    for (const key of updateKeys) {
      const keyHash = await deriveNextKeyHash(key);
      if (!previousNextKeyHashes.includes(keyHash)) {
        throw new Error(`Invalid update key ${keyHash}. Not found in nextKeyHashes ${previousNextKeyHashes}`);
      }
    }
  }

  return true;
};

/**
 * Validate that SCID uses SHA-256 (0x12) multihash algorithm.
 * Per spec: "SHA-256 [[spec:rfc6234]] (multihash code `0x12`) **only**"
 */
const validateScidAlgorithmIsSha256 = (scid: string): void => {
  let algorithm: number;
  try {
    algorithm = decodeMultihash(decodeBase58Btc(scid)).algorithm;
  } catch (error) {
    throw new Error(`Invalid SCID format: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (algorithm !== MultihashAlgorithm.SHA2_256) {
    throw new Error(`SCID multihash algorithm must be SHA-256 (0x12), but got 0x${algorithm.toString(16)}`);
  }
};

export const scidIsFromHash = async (scid: string, hash: string) => {
  validateScidAlgorithmIsSha256(scid);
  return scid === (await createSCID(hash));
};
