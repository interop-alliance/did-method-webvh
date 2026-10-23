import * as crypto from '@stablelib/ed25519';
import { expect, vi } from 'vitest';
import { METHOD, PLACEHOLDER } from '../src/constants.js';
import { AbstractCrypto, createDataIntegrityProofTemplate, prepareDataForSigning } from '../src/cryptography.js';
import { createDIDDoc, replaceCreateDidPlaceholders } from '../src/did-document.js';
import type {
  DataIntegrityProofTemplate,
  DIDLog,
  FetchLike,
  Signer,
  SignerOptions,
  SigningInput,
  SigningOutput,
  VerificationMethod,
  Verifier,
} from '../src/interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { prepareGenesisEntry } from '../src/method_versions/method.v1.0.entries.js';
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
    } catch {
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

/**
 * A DID on example.com controlled by `controller` whose genesis entry requires
 * one witness proof from `witness` (the controller's own key by default).
 */
export const createWitnessedTestDID = ({
  controller,
  witness = controller,
  verifier = createTestVerifier(controller),
}: {
  controller: VerificationMethod;
  witness?: VerificationMethod;
  verifier?: Verifier;
}) =>
  createDID({
    address: 'example.com',
    signer: createTestSigner(controller),
    updateKeys: [controller.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(controller),
    witness: { threshold: 1, witnesses: [{ id: `did:key:${witness.publicKeyMultibase}` }] },
    verifier,
  });

/** The did:key verification method id of a witness's key. */
export const witnessVerificationMethod = (vm: VerificationMethod) =>
  `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`;

/** A witness signing function (the shape `createWitnessProof` takes) backed by a test verification method. */
export const createWitnessSigner = (verificationMethod: VerificationMethod) => {
  const signer = createTestSigner(verificationMethod);
  return async (data: { versionId: string }, proofTemplate?: DataIntegrityProofTemplate) => {
    const proof: DataIntegrityProofTemplate = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: signer.getVerificationMethodId(),
      created: new Date().toISOString(),
      proofPurpose: 'authentication',
      ...proofTemplate,
    };
    const { proofValue } = await signer.sign({ document: data, proof });
    return { proof: { verificationMethod: signer.getVerificationMethodId(), proofValue } };
  };
};

// Stub the global fetch to throw, so a test can prove a custom fetch override
// was used instead.
export const stubGlobalFetchUnused = () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('global fetch should not be called')));
};

// A fetch mock that serves a body per URL suffix (`did.jsonl`,
// `did-witness.json`) and answers `fallbackStatus` (404) for anything else.
export const createRoutedFetchMock = (routes: Record<string, string>, fallbackStatus = 404) =>
  vi.fn(async (url: string) => {
    const match = Object.entries(routes).find(([suffix]) => url.endsWith(suffix));
    return {
      ok: match !== undefined,
      status: match ? 200 : fallbackStatus,
      text: async () => match?.[1] ?? '',
      json: async () => (match ? JSON.parse(match[1]) : null),
    };
  }) as unknown as ReturnType<typeof vi.fn> & FetchLike;

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

/** Creates a DID from `address` (and optional `paths`) and resolves its log. */
export async function createAndResolve(address: string, paths?: string[]) {
  const authKey = await generateTestVerificationMethod();
  const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
  const created = await createDID({
    address,
    paths,
    signer: createTestSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
    verifier,
  });
  const resolved = await resolveDIDFromLog(created.log, { verifier });
  return { created, resolved };
}

/** Asserts that a created DID matches `expectedDid` and resolves cleanly to itself. */
export function expectRoundTrip(
  { created, resolved }: Awaited<ReturnType<typeof createAndResolve>>,
  expectedDid: (scid: string) => string
) {
  const scid = created.log[0].parameters.scid!;
  expect(created.did).toBe(expectedDid(scid));
  expect(created.doc.id).toBe(created.did);
  expect(created.did).not.toContain(PLACEHOLDER);
  expect(resolved.meta.error).toBeUndefined();
  expect(resolved.did).toBe(created.did);
  expect(resolved.doc?.id).toBe(created.did);
  expect(resolved.meta.versionId).toBe(created.log[0].versionId);
}

/**
 * Creates a signed genesis log for `did` exactly as written, bypassing createDID's
 * address canonicalization. Simulates logs written by earlier releases or other
 * implementations (e.g. lowercase hex, uppercase hosts, percent-encoded U-labels).
 */
export async function createUncanonicalizedDID({ did, portable = false }: { did: string; portable?: boolean }) {
  const authKey = await generateTestVerificationMethod();
  const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
  const signer = createTestSigner(authKey);
  const updateKeys = [authKey.publicKeyMultibase!];
  const entry = await prepareGenesisEntry({
    options: {
      address: did,
      portable,
      signer,
      updateKeys,
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    },
    controller: did,
    createdDate: createDate(),
  });
  const created = { did: entry.state.id!, doc: entry.state, log: [entry] as DIDLog };
  const update = (address?: string, paths?: string[]) =>
    updateDID({ log: created.log, signer, updateKeys, verifier, address, paths });
  return { created, scid: entry.parameters.scid!, verifier, signer, updateKeys, update };
}

/** A valid 46-character base58btc SCID for identifier fixtures that never get resolved. */
export const MOCK_SCID = 'QmYEM6EkqHneikXFPD7mEoBi9CeaQgu5F3XMJxXCX44Jcz';
