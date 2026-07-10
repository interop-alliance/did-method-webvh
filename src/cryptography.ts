import type {
  DataIntegrityProof,
  DataIntegrityProofTemplate,
  SignableDocument,
  Signer,
  SignerOptions,
  SigningInput,
  SigningOutput,
  VerificationMethod,
  Verifier,
} from './interfaces.js';
import { concatBuffers } from './utils/buffer.js';
import { canonicalizeStrict } from './utils/canonicalize.js';
import { createHash } from './utils/crypto.js';
import { MultibaseEncoding, multibaseEncode } from './utils/multiformats.js';
import { createDate } from './utils.js';

/**
 * Creates a proof object for a document
 * @param verificationMethodId - The verification method ID to use in the proof
 * @returns A proof object with type, cryptosuite, verificationMethod, created, and proofPurpose
 */
export const createProof = (verificationMethodId: string): DataIntegrityProofTemplate => {
  return {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: verificationMethodId,
    created: createDate(),
    proofPurpose: 'assertionMethod',
  };
};

/**
 * Prepares data for signing by hashing and concatenating the document and proof
 * @param document - The document to sign
 * @param proof - The proof object
 * @returns The prepared data for signing as a Uint8Array
 */
export const prepareDataForSigning = async (
  document: unknown,
  proof: DataIntegrityProofTemplate
): Promise<Uint8Array> => {
  const dataHash = await createHash(canonicalizeStrict(document));
  const proofHash = await createHash(canonicalizeStrict(proof));
  return concatBuffers(proofHash, dataHash);
};

/**
 * Abstract base class for signers
 * Users should extend this class to implement their own signing logic
 */
export abstract class AbstractCrypto implements Signer, Verifier {
  protected verificationMethod?: VerificationMethod | null;
  protected useStaticId: boolean;

  constructor(options: SignerOptions) {
    if (options.verificationMethod) {
      this.verificationMethod = options.verificationMethod;
    }
    this.useStaticId = options.useStaticId !== undefined ? options.useStaticId : true;
  }

  /**
   * Sign the input data
   * @param input - The signing input containing the document and proof
   * @returns The signing output containing the proof value
   */
  abstract sign(input: SigningInput): Promise<SigningOutput>;

  /**
   * Verify a signature
   * @param signature - The signature to verify
   * @param message - The message to verify
   * @param publicKey - The public key to verify the signature with
   */
  abstract verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;

  /**
   * Get the verification method ID
   * @returns The verification method ID
   */
  getVerificationMethodId(): string {
    if (!this.verificationMethod) {
      throw new Error('Verification method not set');
    }
    return this.useStaticId
      ? `did:key:${this.verificationMethod.publicKeyMultibase}#${this.verificationMethod.publicKeyMultibase}`
      : this.verificationMethod.id || '';
  }
}

/**
 * Builds a {@link Signer} around an external signing primitive (KMS, HSM,
 * WebCrypto, hardware wallet) whose key is not raw bytes. Handles the two
 * pieces every such consumer otherwise re-implements: preparing the
 * hash-and-concatenate signing input via {@link prepareDataForSigning}, and
 * multibase-encoding (base58btc) the resulting signature into a `proofValue`.
 *
 * The verification-method id form is load-bearing: the resolver rejects proof
 * verification methods that do not start with `did:key:` and matches the
 * embedded multibase against the log's `updateKeys`, so the id MUST be
 * `did:key:<publicKeyMultibase>#<publicKeyMultibase>` -- which is exactly what
 * this factory emits.
 *
 * @param publicKeyMultibase The signing key's `did:key` multibase (Ed25519
 *   multikey, `z6Mk…`).
 * @param sign Callback that signs the prepared bytes and returns the raw
 *   signature bytes.
 * @returns A `Signer` usable directly by `createDID` / `updateDID`.
 */
export function signerFromExternalKey({
  publicKeyMultibase,
  sign,
}: {
  publicKeyMultibase: string;
  sign(input: { data: Uint8Array }): Promise<Uint8Array>;
}): Signer {
  const verificationMethodId = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`;
  return {
    async sign({ document, proof }) {
      const data = await prepareDataForSigning(document, proof);
      const signature = await sign({ data });
      return {
        proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC),
      };
    },
    getVerificationMethodId() {
      return verificationMethodId;
    },
  };
}

/**
 * Creates a document signer from any Signer implementation
 * @param signer - The signer to use
 * @param verificationMethodId - The verification method ID to use in proofs
 * @returns A function that signs a document and returns the document with proof
 */
export const createDocumentSigner = <TDocument extends SignableDocument>(
  signer: Signer<TDocument>,
  verificationMethodId: string
) => {
  return async (doc: TDocument): Promise<TDocument & { proof: DataIntegrityProof }> => {
    try {
      const proof = createProof(verificationMethodId);
      const result = await signer.sign({ document: doc, proof });

      return { ...doc, proof: { ...proof, proofValue: result.proofValue } };
    } catch (e) {
      console.error(e);
      const message = e instanceof Error ? e.message : String(e);
      throw new Error(`Document signing failure: ${message}`);
    }
  };
};
