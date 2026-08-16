import { beforeAll, describe, expect, test } from 'vitest';
// Everything under test is imported from the package root on purpose: these
// tests double as reachability checks for the generic log-kernel export
// surface (a non-DID log profile must be able to consume the kernel without
// deep imports or a fork).
import {
  buildVersionId,
  canonicalizeStrict,
  createDataIntegrityProofTemplate,
  type DataIntegrityProof,
  deriveHash,
  hashChainIsValid,
  MultibaseEncoding,
  multibaseEncode,
  parseAndValidateVersionId,
  scidIsFromHash,
  signDataIntegrityProof,
  type VerificationMethod,
  verifyEntryProofs,
} from '../src/index.js';
import { createTestVerifier, generateTestVerificationMethod, TestCryptoImplementation } from './utils.js';

// A non-DID verification method id: the kernel must not require `did:key:`;
// which ids are acceptable is entirely the injected authorize/resolveVM's call.
const CONTROLLER_VM_ID = 'did:example:controller#key-1';

describe('verifyEntryProofs (parameterized log kernel)', () => {
  let authKey: VerificationMethod;
  let signedEntry: {
    versionId: string;
    versionTime: string;
    parameters: { method: string };
    state: { type: string; value: number };
    proof: DataIntegrityProof[];
  };

  const resolveTestVM = async (verificationMethod: string) =>
    verificationMethod === CONTROLLER_VM_ID ? { publicKeyMultibase: authKey.publicKeyMultibase } : null;

  const allowAll = () => {};

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    const signer = new TestCryptoImplementation({ verificationMethod: authKey });

    const entry = {
      versionId: '',
      versionTime: '2026-01-01T00:00:00Z',
      parameters: { method: 'test-log:0.1' },
      state: { type: 'TestState', value: 42 },
    };
    const entryHash = await deriveHash(entry);
    const versioned = { ...entry, versionId: buildVersionId(1, entryHash) };

    const proofTemplate = createDataIntegrityProofTemplate({
      verificationMethod: CONTROLLER_VM_ID,
      created: '2026-01-01T00:00:00Z',
    });
    const proof = await signDataIntegrityProof(versioned, proofTemplate, signer);
    signedEntry = { ...versioned, proof: [proof] };
  });

  test('verifies a non-DID entry via injected authorize and resolveVM', async () => {
    const authorizedProofs: DataIntegrityProof[] = [];

    const result = await verifyEntryProofs(signedEntry, {
      verifier: createTestVerifier(authKey),
      authorize: (proof) => {
        authorizedProofs.push(proof);
      },
      resolveVM: resolveTestVM,
    });

    expect(result).toBe(true);
    expect(authorizedProofs).toHaveLength(1);
    expect(authorizedProofs[0].verificationMethod).toBe(CONTROLLER_VM_ID);
  });

  test('a throwing authorize refuses the entry before resolveVM runs', async () => {
    let resolved = false;

    await expect(
      verifyEntryProofs(signedEntry, {
        verifier: createTestVerifier(authKey),
        authorize: () => {
          throw new Error('signer is not in the controller document');
        },
        resolveVM: async (verificationMethod) => {
          resolved = true;
          return resolveTestVM(verificationMethod);
        },
      })
    ).rejects.toThrow('signer is not in the controller document');

    expect(resolved).toBe(false);
  });

  test('an unresolvable verification method is refused', async () => {
    await expect(
      verifyEntryProofs(signedEntry, {
        verifier: createTestVerifier(authKey),
        authorize: allowAll,
        resolveVM: async () => null,
      })
    ).rejects.toThrow(`Verification Method ${CONTROLLER_VM_ID} not found`);
  });

  test('a resolved key without the Ed25519 multikey header is refused', async () => {
    const x25519Key = multibaseEncode(
      new Uint8Array([0xec, 0x01, ...new Uint8Array(32)]),
      MultibaseEncoding.BASE58_BTC
    );

    await expect(
      verifyEntryProofs(signedEntry, {
        verifier: createTestVerifier(authKey),
        authorize: allowAll,
        resolveVM: async () => ({ publicKeyMultibase: x25519Key }),
      })
    ).rejects.toThrow('Unexpected multikey codec: expected 0xed, got 0xec');
  });

  test('a tampered entry fails signature verification', async () => {
    const tampered = { ...signedEntry, state: { ...signedEntry.state, value: 43 } };

    await expect(
      verifyEntryProofs(tampered, {
        verifier: createTestVerifier(authKey),
        authorize: allowAll,
        resolveVM: resolveTestVM,
      })
    ).rejects.toThrow('Proof 0 failed verification');
  });

  test('the proof shape is fixed regardless of the injected authorization', async () => {
    const wrongSuite = {
      ...signedEntry,
      proof: [{ ...signedEntry.proof[0], cryptosuite: 'ecdsa-jcs-2019' as DataIntegrityProof['cryptosuite'] }],
    };

    await expect(
      verifyEntryProofs(wrongSuite, {
        verifier: createTestVerifier(authKey),
        authorize: allowAll,
        resolveVM: resolveTestVM,
      })
    ).rejects.toThrow('Unknown cryptosuite ecdsa-jcs-2019');
  });

  test('a verifier and a proof are required', async () => {
    await expect(
      verifyEntryProofs(signedEntry, {
        authorize: allowAll,
        resolveVM: resolveTestVM,
      })
    ).rejects.toThrow('Verifier implementation is required');

    const { proof: _proof, ...unsigned } = signedEntry;
    await expect(
      verifyEntryProofs(unsigned as { proof?: DataIntegrityProof[] }, {
        verifier: createTestVerifier(authKey),
        authorize: allowAll,
        resolveVM: resolveTestVM,
      })
    ).rejects.toThrow('Missing proof in DID log entry');
  });
});

describe('entry-hash / versionId build steps from the package root', () => {
  test('buildVersionId round-trips through parseAndValidateVersionId', async () => {
    const entryHash = await deriveHash({ any: 'entry' });
    const versionId = buildVersionId(3, entryHash);

    expect(parseAndValidateVersionId(versionId, 3)).toEqual({
      version: '3',
      versionNumber: 3,
      entryHash,
    });
  });

  test('deriveHash hashes the canonicalizeStrict form and chains via hashChainIsValid', async () => {
    const entry = { b: 2, a: 1 };
    expect(canonicalizeStrict(entry)).toBe('{"a":1,"b":2}');

    const hash = await deriveHash(entry);
    expect(hashChainIsValid(await deriveHash({ a: 1, b: 2 }), hash)).toBe(true);
    // The SCID convention is the genesis entry hash itself.
    expect(await scidIsFromHash(hash, hash)).toBe(true);
  });
});
