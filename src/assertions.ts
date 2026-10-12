import {
  hashCanonicalDocument,
  prepareDataForSigning,
  resolvePublicKeyMultibase,
  validateWebvhProofShape,
} from './cryptography.js';
import type { DataIntegrityProof, DIDLogEntry, ResolveVerificationMethod, Verifier } from './interfaces.js';
import { deriveNextKeyHash } from './utils/crypto.js';
import {
  decodeBase58Btc,
  decodeEd25519Multikey,
  decodeMultihash,
  MultihashAlgorithm,
  multibaseDecode,
} from './utils/multiformats.js';
import { parseDidKeyVerificationMethod } from './utils.js';

const isKeyAuthorized = (verificationMethod: string, updateKeys: string[]): boolean => {
  return updateKeys.includes(parseDidKeyVerificationMethod(verificationMethod).keyMultibase);
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
 * the did:webvh method is one caller, via `documentStateIsValid`. Resolves
 * only after every proof in the array verified, in order, throwing on the
 * first failure; callers that defer policy checks until after the call
 * depend on this.
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
    resolveVM: ResolveVerificationMethod;
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

  let entryHash: Uint8Array | undefined;
  for (let i = 0; i < proofs.length; i++) {
    const proof = proofs[i];

    await authorize(proof);

    validateWebvhProofShape(proof, (field, value) => {
      if (field === 'type') return `Unknown proof type ${value}`;
      if (field === 'proofPurpose') {
        return `Invalid proof purpose '${value}' for DID log entry proof. Expected 'assertionMethod'.`;
      }
      return `Unknown cryptosuite ${value}`;
    });

    const publicKey = decodeEd25519Multikey(await resolvePublicKeyMultibase(resolveVM, proof.verificationMethod));

    const { proofValue, ...restProof } = proof;
    const signature = multibaseDecode(proofValue).bytes;
    entryHash ??= await hashCanonicalDocument(rest);
    const input = await prepareDataForSigning(rest, restProof, { documentHash: entryHash });

    const verified = await verifier.verify(signature, input, publicKey);

    if (!verified) {
      throw new Error(`Proof ${i} failed verification (proofValue: ${proofValue})`);
    }
  }
  return true;
};

export const documentStateIsValid = async (
  entry: DIDLogEntry,
  {
    updateKeys,
    verifier,
    resolveVM,
  }: {
    updateKeys: string[];
    verifier?: Verifier;
    /** Injected by the method layer; the default lives in `vm-resolver.ts`. */
    resolveVM: ResolveVerificationMethod;
  }
) => {
  return verifyEntryProofs(entry, {
    verifier,
    authorize: (proof) => {
      if (!proof.verificationMethod.startsWith('did:key:')) {
        throw new Error(`Unsupported verification method for DID log entry authorization: ${proof.verificationMethod}`);
      }

      if (!isKeyAuthorized(proof.verificationMethod, updateKeys)) {
        throw new Error(`Key ${proof.verificationMethod} is not authorized to update.`);
      }
    },
    resolveVM,
  });
};

export const hashChainIsValid = (derivedHash: string, logEntryHash: string) => {
  return derivedHash === logEntryHash;
};

export const newKeysAreInNextKeys = async (updateKeys: string[], previousNextKeyHashes: string[]): Promise<void> => {
  if (previousNextKeyHashes.length === 0) {
    return;
  }

  for (const key of updateKeys) {
    const keyHash = await deriveNextKeyHash(key);
    if (!previousNextKeyHashes.includes(keyHash)) {
      throw new Error(`Invalid update key ${keyHash}. Not found in nextKeyHashes ${previousNextKeyHashes}`);
    }
  }
};

const isEd25519Multikey = (value: string): boolean => {
  try {
    decodeEd25519Multikey(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * Validates a `nextKeyHashes` list: every entry must be a bare base58btc
 * SHA-256 multihash, as produced by `deriveNextKeyHash`. Rejects a `did:key`
 * or multikey passed in place of its hash, which would otherwise yield a log
 * that can no longer rotate keys. Returns a fresh copy of the list.
 */
export const assertValidNextKeyHashes = (nextKeyHashes: unknown, context = 'nextKeyHashes'): string[] => {
  if (!Array.isArray(nextKeyHashes)) {
    throw new Error(`${context} must be an array of derived pre-rotation key hashes`);
  }

  return nextKeyHashes.map((nextKeyHash, index) => {
    const label = `${context}[${index}]`;
    if (typeof nextKeyHash !== 'string' || nextKeyHash.length === 0) {
      throw new Error(`${label} must be a non-empty derived pre-rotation key hash`);
    }

    if (nextKeyHash.startsWith('did:key:')) {
      throw new Error(
        `${label} must be a derived pre-rotation key hash, not a did:key. Use deriveNextKeyHash() first.`
      );
    }

    try {
      decodeMultihash(decodeBase58Btc(nextKeyHash), MultihashAlgorithm.SHA2_256);
    } catch (hashError) {
      if (isEd25519Multikey(nextKeyHash)) {
        throw new Error(
          `${label} must be a derived pre-rotation key hash, not an Ed25519 multikey. Use deriveNextKeyHash() first.`
        );
      }
      const message = hashError instanceof Error ? hashError.message : String(hashError);
      throw new Error(`${label} must be a base58btc-encoded SHA-256 multihash: ${message}`);
    }
    return nextKeyHash;
  });
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
  return scid === hash;
};
