import {
  AbstractCrypto,
  createDID,
  MultibaseEncoding,
  multibaseDecode,
  multibaseEncode,
  prepareDataForSigning,
} from '@interop/did-method-webvh';
import type {
  Signer,
  SigningInput,
  SigningOutput,
  VerificationMethod,
  Verifier,
} from '@interop/did-method-webvh/types';
import { generateKeyPair, sign, verify } from '@stablelib/ed25519';

/**
 * The key material an `ExampleCrypto` signs with. Distinct from the public
 * `VerificationMethod` published into the DID document: `secretKeyMultibase`
 * must never leave this process.
 */
type SigningKey = Required<Pick<VerificationMethod, 'id' | 'controller' | 'type' | 'publicKeyMultibase'>> & {
  secretKeyMultibase: string;
};

class ExampleCrypto extends AbstractCrypto implements Verifier, Signer {
  constructor(public readonly verificationMethod: SigningKey) {
    super({ verificationMethod });
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    try {
      const { bytes: secretKey } = multibaseDecode(this.verificationMethod.secretKeyMultibase);
      const proof = sign(secretKey.slice(2), await prepareDataForSigning(input.document, input.proof));
      return {
        proofValue: multibaseEncode(proof, MultibaseEncoding.BASE58_BTC),
      };
    } catch (error) {
      console.error('Ed25519 signing error:', error);
      throw error;
    }
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return verify(publicKey, message, signature);
    } catch (error) {
      console.error('Ed25519 verification error:', error);
      return false;
    }
  }

  getVerificationMethodId(): string {
    return this.verificationMethod.id;
  }
}

/**
 * Generates a fresh Ed25519 keypair and returns two things derived from it:
 * a `signingKey` (carries `secretKeyMultibase`, used only to build the local
 * `Signer`/`Verifier`) and a public-only `verificationMethod` for the DID
 * document. The two must stay separate -- a caller-supplied `verificationMethods`
 * entry that still carries `secretKeyMultibase` is rejected by `createDID`.
 */
export async function generateEd25519KeyMaterial(): Promise<{
  signingKey: SigningKey;
  verificationMethod: VerificationMethod;
}> {
  const { secretKey, publicKey } = generateKeyPair();
  const publicKeyMultibase = multibaseEncode(new Uint8Array([0xed, 0x01, ...publicKey]), MultibaseEncoding.BASE58_BTC);
  const didKey = `did:key:${publicKeyMultibase}`;

  return {
    signingKey: {
      id: `${didKey}#${publicKeyMultibase}`,
      type: 'Multikey',
      controller: didKey,
      publicKeyMultibase,
      secretKeyMultibase: multibaseEncode(new Uint8Array([0x80, 0x26, ...secretKey]), MultibaseEncoding.BASE58_BTC),
    },
    verificationMethod: {
      id: `{DID}#${publicKeyMultibase.slice(-8)}`,
      type: 'Multikey',
      controller: '{DID}',
      publicKeyMultibase,
      purpose: 'assertionMethod',
    },
  };
}

export const createExampleCrypto = async (signingKey: SigningKey) => new ExampleCrypto(signingKey);

const { signingKey, verificationMethod } = await generateEd25519KeyMaterial();

const crypto = await createExampleCrypto(signingKey);

const did = await createDID({
  address: 'example.com',
  signer: crypto,
  verifier: crypto,
  updateKeys: [signingKey.publicKeyMultibase],
  verificationMethods: [verificationMethod],
});

console.log(did);
