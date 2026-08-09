import * as crypto from '@stablelib/ed25519';
import { METHOD, PLACEHOLDER } from '../src/constants.js';
import { AbstractCrypto, createDataIntegrityProofTemplate, prepareDataForSigning } from '../src/cryptography.js';
import { createDIDDoc, replaceCreateDidPlaceholders } from '../src/did-document.js';
import type {
  DIDLog,
  Signer,
  SignerOptions,
  SigningInput,
  SigningOutput,
  VerificationMethod,
  Verifier,
} from '../src/interfaces.js';
import { deriveHash } from '../src/utils/crypto.js';
import { createDate } from '../src/utils/iso8601-datetime.js';
import { MultibaseEncoding, multibaseDecode, multibaseEncode } from '../src/utils/multiformats.js';
import { buildVersionId } from '../src/utils.js';

/** Returns the versionTime one second after the last entry in a DID log. Use in tests when chaining rapid create/update/deactivate calls. */
export const nextSecond = (log: DIDLog): string =>
  createDate(new Date(new Date(log[log.length - 1].versionTime).getTime() + 1000));

// Test crypto implementation
export class TestCryptoImplementation extends AbstractCrypto implements Verifier {
  private keyPair: { publicKey: Uint8Array; secretKey: Uint8Array };

  constructor(options: SignerOptions) {
    super(options);
    if (!options.verificationMethod?.secretKeyMultibase || !options.verificationMethod.publicKeyMultibase) {
      throw new Error('TestCryptoImplementation requires secret and public multibase keys');
    }

    const secretKey = multibaseDecode(options.verificationMethod.secretKeyMultibase).bytes;
    const publicKey = multibaseDecode(options.verificationMethod.publicKeyMultibase).bytes;
    this.keyPair = { publicKey, secretKey };
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    const signature = crypto.sign(this.keyPair.secretKey.slice(2), dataToSign);
    return { proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC) };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return crypto.verify(publicKey, message, signature);
    } catch (error) {
      console.error('Error verifying signature:', error);
      return false;
    }
  }
}

// Helper to generate verification method for tests
type TestPurpose =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

export async function generateTestVerificationMethod(
  purpose: TestPurpose | TestPurpose[] = 'authentication',
  id?: string
): Promise<VerificationMethod> {
  const keyPair = crypto.generateKeyPair();
  const secretKey = multibaseEncode(new Uint8Array([0x80, 0x26, ...keyPair.secretKey]), MultibaseEncoding.BASE58_BTC);
  const publicKey = multibaseEncode(new Uint8Array([0xed, 0x01, ...keyPair.publicKey]), MultibaseEncoding.BASE58_BTC);
  return {
    id,
    type: 'Multikey',
    publicKeyMultibase: publicKey,
    secretKeyMultibase: secretKey,
    purpose,
  };
}

// Helper to create a signer from a verification method
export function createTestSigner(verificationMethod: VerificationMethod): Signer {
  return new TestCryptoImplementation({ verificationMethod });
}

// Helper to create a test verifier
export function createTestVerifier(verificationMethod: VerificationMethod): Verifier {
  return new TestCryptoImplementation({ verificationMethod });
}

// Helper to produce DID document-safe verification methods by stripping secret key material
export function asPublicVerificationMethods(...verificationMethods: VerificationMethod[]): VerificationMethod[] {
  return verificationMethods.map((verificationMethod) => {
    const { secretKeyMultibase, ...publicVerificationMethod } = verificationMethod;
    return publicVerificationMethod;
  });
}

// Helper to build a single-entry DID log whose versionTime is `minutesAhead`
// minutes in the future, used to exercise the resolver's clock-skew tolerance.
export const createFutureDIDLog = async (authKey: VerificationMethod, minutesAhead: number): Promise<DIDLog> => {
  const futureCreated = new Date(Date.now() + minutesAhead * 60 * 1000).toISOString();
  const signer = createTestSigner(authKey);
  const controller = `did:${METHOD}:${PLACEHOLDER}:example.com`;

  const doc = createDIDDoc({
    did: controller,
    verificationMethods: asPublicVerificationMethods(authKey),
  });

  const initialLogEntry: DIDLog[0] = {
    versionId: PLACEHOLDER,
    versionTime: futureCreated,
    parameters: {
      method: `did:${METHOD}:1.0`,
      scid: PLACEHOLDER,
      updateKeys: [authKey.publicKeyMultibase!],
      portable: false,
      nextKeyHashes: [],
      watchers: [],
      witness: {},
      deactivated: false,
    },
    state: doc,
  };

  const scid = await deriveHash(initialLogEntry);
  const did = `did:${METHOD}:${scid}:example.com`;
  const prelimEntry = replaceCreateDidPlaceholders(initialLogEntry, scid, did);
  const logEntryHash = await deriveHash(prelimEntry);
  prelimEntry.versionId = buildVersionId(1, logEntryHash);

  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod: signer.getVerificationMethodId(),
    created: futureCreated,
    proofPurpose: 'assertionMethod',
  });
  const signedProof = await signer.sign({ document: prelimEntry, proof: proofTemplate });
  prelimEntry.proof = [{ ...proofTemplate, proofValue: signedProof.proofValue }];

  return [prelimEntry];
};
