import type { ISigner } from '@interop/data-integrity-core';
import { VerificationMethodError } from '@interop/data-integrity-core';
import type {
  DataIntegrityProof,
  DataIntegrityProofPurpose,
  DataIntegrityProofTemplate,
  ResolveVerificationMethod,
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
import { createDate } from './utils/iso8601-datetime.js';
import { MultibaseEncoding, multibaseEncode } from './utils/multiformats.js';

/**
 * Creates a Data Integrity proof template from explicit input values.
 */
export const createDataIntegrityProofTemplate = (options: {
  verificationMethod: string;
  created?: string;
  proofPurpose?: DataIntegrityProofPurpose;
  id?: string;
}): DataIntegrityProofTemplate => {
  return {
    ...(options.id ? { id: options.id } : {}),
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: options.verificationMethod,
    created: options.created ?? createDate(),
    proofPurpose: options.proofPurpose ?? 'assertionMethod',
  };
};

/**
 * Signs a document using a proof template and returns a complete DataIntegrityProof.
 */
export const signDataIntegrityProof = async <TDocument>(
  document: TDocument,
  proofTemplate: DataIntegrityProofTemplate,
  signer: Signer<TDocument>
): Promise<DataIntegrityProof> => {
  const { proofValue } = await signer.sign({ document, proof: proofTemplate });

  const verificationMethod = proofTemplate.verificationMethod;
  if (!verificationMethod) {
    throw new Error('Data Integrity proof is missing verificationMethod');
  }

  if (!proofValue) {
    throw new Error('Data Integrity proof is missing proofValue');
  }

  // `id` is emitted only when the template carries one; an unconditional
  // `id: undefined` would leave an own key on every serialized log entry proof.
  return {
    ...(proofTemplate.id ? { id: proofTemplate.id } : {}),
    type: proofTemplate.type,
    cryptosuite: proofTemplate.cryptosuite,
    verificationMethod,
    created: proofTemplate.created,
    proofValue,
    proofPurpose: proofTemplate.proofPurpose,
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
  proof: DataIntegrityProofTemplate,
  precomputed?: { documentHash?: Uint8Array }
): Promise<Uint8Array> => {
  const dataHash = precomputed?.documentHash ?? (await hashCanonicalDocument(document));
  const proofHash = await hashCanonicalDocument(proof);
  return concatBuffers(proofHash, dataHash);
};

/** SHA-256 over the JCS canonicalization of a value (the eddsa-jcs-2022 hash side). */
export const hashCanonicalDocument = async (value: unknown): Promise<Uint8Array> => {
  return createHash(canonicalizeStrict(value));
};

/**
 * The webvh proof-shape rule (`DataIntegrityProof` / `assertionMethod` /
 * `eddsa-jcs-2022`), checked in one place; `message` renders each caller's
 * historical error wording for the failing field.
 */
export const validateWebvhProofShape = (
  proof: Pick<DataIntegrityProof, 'type' | 'proofPurpose' | 'cryptosuite'>,
  message: (field: 'type' | 'proofPurpose' | 'cryptosuite', value: string) => string
): void => {
  if (proof.type !== 'DataIntegrityProof') {
    throw new Error(message('type', proof.type));
  }
  if (proof.proofPurpose !== 'assertionMethod') {
    throw new Error(message('proofPurpose', proof.proofPurpose));
  }
  if (proof.cryptosuite !== 'eddsa-jcs-2022') {
    throw new Error(message('cryptosuite', proof.cryptosuite));
  }
};

/**
 * Resolves a proof's verification method to its `publicKeyMultibase`.
 *
 * @throws {VerificationMethodError} With code `notFound` when the resolver
 *   returns no method, or one without a public key.
 */
export const resolvePublicKeyMultibase = async (
  resolveVM: ResolveVerificationMethod,
  verificationMethod: string
): Promise<string> => {
  const vm = await resolveVM(verificationMethod);
  if (!vm?.publicKeyMultibase) {
    throw new VerificationMethodError(`Verification Method ${verificationMethod} not found`, {
      code: 'notFound',
      verificationMethod,
    });
  }
  return vm.publicKeyMultibase;
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
   * The default did:key ID can be supplied in updateKeys to createDID, updateDID,
   * or deactivateDID; those APIs store its bare multikey in the log. Derive
   * nextKeyHashes from the bare publicKeyMultibase, not this ID.
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
 *   multikey, `z6Mk...`).
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
  return signerOverRawSign({
    verificationMethodId: `did:key:${publicKeyMultibase}#${publicKeyMultibase}`,
    sign,
  });
}

/**
 * Builds a {@link Signer} around a raw-bytes `ISigner` (the shape
 * `@interop/ed25519-verification-key`'s `signer()` and `didKeySigner()`
 * return, and `@interop/capability-agent`'s `getSigner()`): the signer's `id`
 * is taken verbatim as the proof's verification-method id, and its
 * `sign({ data })` signs the prepared bytes. The id must already be in the
 * `did:key:<publicKeyMultibase>#<publicKeyMultibase>` form the resolver
 * matches against the log's `updateKeys`; a signer named under any other DID
 * is refused here rather than at verification time.
 *
 * @param signer A raw-bytes signer carrying its own `did:key` id.
 * @returns A `Signer` usable directly by `createDID` / `updateDID`.
 */
export function signerFromDidKeySigner(signer: ISigner): Signer {
  if (!DID_KEY_VERIFICATION_METHOD_ID.test(signer.id)) {
    throw new Error(
      `Signer id must be of the form did:key:<publicKeyMultibase>#<publicKeyMultibase>; got "${signer.id}".`
    );
  }
  return signerOverRawSign({
    verificationMethodId: signer.id,
    sign: (input) => signer.sign(input),
  });
}

const DID_KEY_VERIFICATION_METHOD_ID = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)#\1$/;

function signerOverRawSign({
  verificationMethodId,
  sign,
}: {
  verificationMethodId: string;
  sign(input: { data: Uint8Array }): Promise<Uint8Array>;
}): Signer {
  return {
    async sign({ document, proof }) {
      const data = await prepareDataForSigning(document, proof);
      const signature = await sign({ data });
      // Re-wrap as a plain Uint8Array: a raw signer may hand back a Node
      // Buffer or a cross-realm view, which the multibase encoder's strict
      // byte check rejects.
      const bytes = new Uint8Array(signature.buffer, signature.byteOffset, signature.byteLength);
      return {
        proofValue: multibaseEncode(bytes, MultibaseEncoding.BASE58_BTC),
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
 * @param verificationMethodId - The verification method ID to use when building proof templates
 * @returns A function that signs a document and returns the document with proof
 */
export const createDocumentSigner = <TDocument extends SignableDocument>(
  signer: Signer<TDocument>,
  verificationMethodId: string
) => {
  return async (doc: TDocument): Promise<TDocument & { proof: DataIntegrityProof }> => {
    try {
      const proofTemplate = createDataIntegrityProofTemplate({ verificationMethod: verificationMethodId });
      const proof = await signDataIntegrityProof(doc, proofTemplate, signer);

      return { ...doc, proof };
    } catch (e) {
      console.error(e);
      const message = e instanceof Error ? e.message : String(e);
      throw new Error(`Document signing failure: ${message}`);
    }
  };
};
