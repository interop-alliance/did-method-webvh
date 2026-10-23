import { beforeAll, describe, expect, test, vi } from 'vitest';
import { createDataIntegrityProofTemplate, signDataIntegrityProof } from '../src/cryptography.js';
import type {
  CreateDIDResult,
  DataIntegrityProofTemplate,
  DIDLogEntry,
  Signer,
  VerificationMethod,
} from '../src/interfaces.js';
import { createDID, deactivateDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { deriveHash } from '../src/utils/crypto.js';
import { MultibaseEncoding, multibaseEncode } from '../src/utils/multiformats.js';
import { parseDidKeyDid, parseDidKeyVerificationMethod } from '../src/utils.js';
import { createWitnessProof } from '../src/witness.js';
import { signWitnessProofEntry } from '../src/witness-signing.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  createWitnessedTestDID,
  createWitnessSigner,
  generateTestVerificationMethod,
  nextSecond,
  TestCryptoImplementation,
  witnessVerificationMethod,
} from './utils.js';

describe('Witness Implementation Tests', async () => {
  let authKey: VerificationMethod;
  let witness1: VerificationMethod, witness2: VerificationMethod, witness3: VerificationMethod;
  let initialDID: CreateDIDResult;
  let testImplementation: TestCryptoImplementation;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    witness1 = await generateTestVerificationMethod();
    witness2 = await generateTestVerificationMethod();
    witness3 = await generateTestVerificationMethod();
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey });
  });

  test('Create DID with witness threshold', async () => {
    initialDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    expect(initialDID.meta?.witness?.threshold).toBe(2);
    expect(initialDID.meta?.witness?.witnesses).toHaveLength(2);
  });

  test('Resolve DID with witness proofs meeting threshold', async () => {
    // Create witness proofs for the initial DID's version
    const versionId = initialDID.log[0].versionId;

    // Create proofs from witness1 and witness2 using their signers
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);

    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2)),
    ]);

    const witnessProofs = [
      {
        versionId,
        proof: proofs,
      },
    ];

    // Resolve the DID log with witness proofs
    const resolved = await resolveDIDFromLog(initialDID.log, {
      witnessProofs,
      verifier: testImplementation,
    });

    expect(resolved.meta?.witness?.threshold).toBe(2);
    expect(resolved.did).toBe(initialDID.did);
  });

  test('Create DID without witnesses then update to add witnesses', async () => {
    // Create initial DID without witnesses
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const newAuthKey = await generateTestVerificationMethod();

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      updated: nextSecond(noWitnessDID.log),
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(newAuthKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    // Create witness proofs for the new version
    const newVersionId = updatedDID.log[1].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);

    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, newVersionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, newVersionId, witnessVerificationMethod(witness2)),
    ]);

    const witnessProofs = [
      {
        versionId: newVersionId,
        proof: proofs,
      },
    ];

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs,
    });
    expect(resolved.meta?.witness?.threshold).toBe(2);
    expect(updatedDID.log).toHaveLength(2);
    expect(resolved.meta?.witness?.witnesses).toHaveLength(2);
  });

  test('Resolve DID rejects duplicate witness IDs in witness parameters', async () => {
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const duplicateWitnessId = `did:key:${witness1.publicKeyMultibase}`;
    const newAuthKey = await generateTestVerificationMethod();

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      updated: nextSecond(noWitnessDID.log),
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(newAuthKey),
      verifier: testImplementation,
    });

    const duplicateWitnessEntry = JSON.parse(JSON.stringify(updatedDID.log[1]));
    duplicateWitnessEntry.parameters.witness = {
      threshold: 2,
      witnesses: [{ id: duplicateWitnessId }, { id: duplicateWitnessId }],
    };

    delete duplicateWitnessEntry.proof;
    const logEntryHash = await deriveHash({
      ...duplicateWitnessEntry,
      versionId: updatedDID.log[0].versionId,
    });
    duplicateWitnessEntry.versionId = `2-${logEntryHash}`;

    const signer = createTestSigner(authKey);
    const proofTemplate: DataIntegrityProofTemplate = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: signer.getVerificationMethodId(),
      created: duplicateWitnessEntry.versionTime,
      proofPurpose: 'assertionMethod' as const,
    };
    const signedProof = await signer.sign({ document: duplicateWitnessEntry, proof: proofTemplate });
    duplicateWitnessEntry.proof = [{ ...proofTemplate, proofValue: signedProof.proofValue }];

    const tamperedLog = [updatedDID.log[0], duplicateWitnessEntry];

    await expect(
      resolveDIDFromLog(tamperedLog, {
        verifier: testImplementation,
      })
    ).rejects.toThrow(`Duplicate witness id: ${duplicateWitnessId}`);
  });

  test('rejects witness did:key with incompatible key type at parameter validation', async () => {
    // Build a non-Ed25519 multikey payload (header != 0xed01), but still valid multibase.
    const nonEd25519Multikey = multibaseEncode(
      new Uint8Array([0xe7, 0x01, ...new Uint8Array(32).fill(7)]),
      MultibaseEncoding.BASE58_BTC
    );
    const invalidWitnessDid = `did:key:${nonEd25519Multikey}`;

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        witness: {
          threshold: 1,
          witnesses: [{ id: invalidWitnessDid }],
        },
        verifier: testImplementation,
      })
    ).rejects.toThrow(/Witness DID key type must be Ed25519/);
  });

  test('API e2e: create, update, witness, and resolve with raw multibase updateKeys', async () => {
    const authKey2 = await generateTestVerificationMethod();

    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    const version1Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      created.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    const updated = await updateDID({
      log: created.log,
      updated: nextSecond(created.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey2.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey2),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
      ],
    });

    const version2Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      updated.log[1].versionId,
      witnessVerificationMethod(witness1)
    );

    const resolved = await resolveDIDFromLog(updated.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
        {
          versionId: updated.log[1].versionId,
          proof: [version2Proof],
        },
      ],
    });

    expect(resolved.did).toBe(updated.did);
    expect(resolved.meta?.updateKeys).toEqual([authKey2.publicKeyMultibase!]);
  });

  test('API e2e: normalizes did:key-formatted updateKeys in update flow', async () => {
    const authKey2 = await generateTestVerificationMethod();
    const authKey3 = await generateTestVerificationMethod();

    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    const version1Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      created.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    const firstUpdate = await updateDID({
      log: created.log,
      updated: nextSecond(created.log),
      signer: createTestSigner(authKey),
      updateKeys: [`did:key:${authKey2.publicKeyMultibase}`],
      verificationMethods: asPublicVerificationMethods(authKey2),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
      ],
    });

    const version2Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      firstUpdate.log[1].versionId,
      witnessVerificationMethod(witness1)
    );

    expect(firstUpdate.log[1].parameters.updateKeys).toEqual([authKey2.publicKeyMultibase!]);

    const secondUpdate = await updateDID({
      log: firstUpdate.log,
      updated: nextSecond(firstUpdate.log),
      signer: createTestSigner(authKey2),
      updateKeys: [authKey3.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey3),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
        {
          versionId: firstUpdate.log[1].versionId,
          proof: [version2Proof],
        },
      ],
    });
    expect(secondUpdate.log).toHaveLength(3);
    expect(secondUpdate.meta.updateKeys).toEqual([authKey3.publicKeyMultibase!]);
  });

  test('API e2e: rejects did:webvh verificationMethod in DID log entry proof', async () => {
    const authKey2 = await generateTestVerificationMethod();

    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const baseSigner = createTestSigner(authKey);
    const nonCompliantSigner: Signer = {
      sign: (input) => baseSigner.sign(input),
      getVerificationMethodId: () => `${created.did}#controller-key`,
    };

    await expect(
      updateDID({
        log: created.log,
        updated: nextSecond(created.log),
        signer: nonCompliantSigner,
        updateKeys: [authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey2),
        verifier: testImplementation,
      })
    ).rejects.toThrow('Unsupported verification method for DID log entry authorization');
  });

  test('Replace witness list with new witnesses', async () => {
    const newWitness = await generateTestVerificationMethod();

    // Create proofs for initial version
    const versionId = initialDID.log[0].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2)),
    ]);
    const witnessProofs = [{ versionId, proof: proofs }];

    const updatedDID = await updateDID({
      log: initialDID.log,
      updated: nextSecond(initialDID.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${newWitness.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
      witnessProofs,
    });

    // The replacing entry is governed by the previous list, so v2 needs witness1 + witness2.
    const newVersionId = updatedDID.log[1].versionId;
    const newWitnessProofs = [
      {
        versionId: newVersionId,
        proof: await Promise.all([
          createWitnessProof(createWitnessSigner(witness1), newVersionId, witnessVerificationMethod(witness1)),
          createWitnessProof(createWitnessSigner(witness2), newVersionId, witnessVerificationMethod(witness2)),
        ]),
      },
    ];

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs: [...witnessProofs, ...newWitnessProofs],
    });
    expect(resolved.meta?.witness?.witnesses).toHaveLength(1);
    expect(resolved.meta?.witness?.threshold).toBe(1);
  });

  test('Omitting witness on update retains the active witness configuration', async () => {
    const proofsFor = async (versionId: string) => ({
      versionId,
      proof: await Promise.all([
        createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
        createWitnessProof(createWitnessSigner(witness2), versionId, witnessVerificationMethod(witness2)),
      ]),
    });
    const v1Proofs = [await proofsFor(initialDID.log[0].versionId)];

    const v2 = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      verifier: testImplementation,
      witnessProofs: v1Proofs,
    });

    expect(v2.log[1].parameters).not.toHaveProperty('witness');
    expect(v2.meta.witness).toEqual(initialDID.meta.witness);

    const unwitnessed = await resolveDIDFromLog(v2.log, {
      versionNumber: 1,
      verifier: testImplementation,
      witnessProofs: v1Proofs,
    });
    expect(unwitnessed.meta.error).toBe('invalidDid');

    const allProofs = [...v1Proofs, await proofsFor(v2.log[1].versionId)];
    const resolved = await resolveDIDFromLog(v2.log, { verifier: testImplementation, witnessProofs: allProofs });
    expect(resolved.meta.error).toBeUndefined();
    expect(resolved.meta.witness).toEqual(initialDID.meta.witness);
  });

  test('Disable witnessing by setting witness list to null', async () => {
    // Create proofs for initial version
    const versionId = initialDID.log[0].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2)),
    ]);
    const witnessProofs = [{ versionId, proof: proofs }];

    const updatedDID = await updateDID({
      log: initialDID.log,
      updated: nextSecond(initialDID.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: null,
      verifier: testImplementation,
      witnessProofs,
    });

    const newVersionId = updatedDID.log[1].versionId;
    const deactivationProofs = await Promise.all([
      createWitnessProof(createWitnessSigner(witness1), newVersionId, witnessVerificationMethod(witness1)),
      createWitnessProof(createWitnessSigner(witness2), newVersionId, witnessVerificationMethod(witness2)),
    ]);

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs: [...witnessProofs, { versionId: newVersionId, proof: deactivationProofs }],
    });
    expect(resolved.meta.witness).toEqual({});
  });

  test('a subsequent entry with a literal witness: null resolves to meta.witness === {}', async () => {
    const key = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: key });
    const signer = createTestSigner(key);

    const created = await createDID({
      address: 'example.com',
      signer,
      updateKeys: [key.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(key),
      verifier,
    });
    const genesis = created.log[0];

    // Hand-build a second entry whose parameters carry a *literal* `witness: null`.
    // The public updateDID normalizes a null witness to `{}`, so this raw shape is
    // only reachable from an externally authored log; resolution normalizes it to
    // `{}` via resolveWitnessParameter, matching what updateDID reports for the
    // same cleared-witness state.
    const parameters = { witness: null } as unknown as DIDLogEntry['parameters'];
    const logEntry: DIDLogEntry = {
      versionId: genesis.versionId,
      versionTime: nextSecond(created.log),
      parameters,
      state: structuredClone(genesis.state),
    };
    const entryHash = await deriveHash(logEntry);
    const entry: DIDLogEntry = { ...logEntry, versionId: `2-${entryHash}` };
    const proofTemplate = createDataIntegrityProofTemplate({
      verificationMethod: signer.getVerificationMethodId(),
      created: logEntry.versionTime,
      proofPurpose: 'assertionMethod',
    });
    entry.proof = [await signDataIntegrityProof(entry, proofTemplate, signer)];

    const resolved = await resolveDIDFromLog([genesis, entry], { verifier });
    expect(resolved.meta.witness).toEqual({});
  });

  test('Verify witness proofs from did-witness.json', async () => {
    // Create real witness proofs using the utility
    const mockWitnessFile = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            initialDID.log[0].versionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness2),
            initialDID.log[0].versionId,
            witnessVerificationMethod(witness2)
          ),
        ],
      },
      {
        versionId: 'future-version-id',
        proof: [
          // This proof should be ignored since version doesn't exist in log
          await createWitnessProof(
            createWitnessSigner(witness1),
            'future-version-id',
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ];

    const resolved = await resolveDIDFromLog(initialDID.log, {
      witnessProofs: mockWitnessFile,
      verifier: testImplementation,
    });

    expect(resolved.did).toBe(initialDID.did);
  });

  test('Reject witness proofs with invalid proofPurpose', async () => {
    const badProof = await createWitnessProof(
      createWitnessSigner(witness1),
      initialDID.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    const witnessProofs = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          {
            ...badProof,
            proofPurpose: 'authentication' as const,
          },
        ],
      },
    ];

    await expect(
      resolveDIDFromLog(initialDID.log, {
        witnessProofs,
        verifier: testImplementation,
      })
    ).rejects.toThrow(`Witness threshold not met for version ${initialDID.log[0].versionId}`);
  });

  test('parseDidKeyDid accepts a valid did:key DID', () => {
    const did = `did:key:${witness1.publicKeyMultibase}`;

    expect(parseDidKeyDid(did)).toEqual({
      did,
      keyMultibase: witness1.publicKeyMultibase!,
    });
  });

  test('parseDidKeyDid rejects malformed DID input', () => {
    expect(() => parseDidKeyDid(`did:key:${witness1.publicKeyMultibase}#fragment`)).toThrow('Malformed did:key DID');
    expect(() => parseDidKeyDid('did:web:example.com')).toThrow('Malformed did:key DID');
  });

  test('parseDidKeyVerificationMethod accepts fragment and no-fragment forms', () => {
    const withFragment = witnessVerificationMethod(witness1);
    const withoutFragment = `did:key:${witness1.publicKeyMultibase}`;

    expect(parseDidKeyVerificationMethod(withFragment)).toEqual({
      did: withoutFragment,
      fragment: witness1.publicKeyMultibase,
      keyMultibase: witness1.publicKeyMultibase!,
    });
    expect(parseDidKeyVerificationMethod(withoutFragment)).toEqual({
      did: withoutFragment,
      fragment: undefined,
      keyMultibase: witness1.publicKeyMultibase!,
    });
  });

  test('parseDidKeyVerificationMethod rejects relative and non-did:key values', () => {
    expect(() => parseDidKeyVerificationMethod(`#${witness1.publicKeyMultibase}`)).toThrow(
      'did:key verificationMethod must be an absolute DID URL'
    );
    expect(() => parseDidKeyVerificationMethod('did:web:example.com#key-1')).toThrow(
      'Malformed did:key verificationMethod'
    );
  });

  test('parseDidKeyVerificationMethod rejects fragment that differs from body multibase', () => {
    const validMultibase = witness1.publicKeyMultibase!;
    const differentMultibase = 'z6MkhaXgBZDvotzL8V6N3XQfZ47fRhVvKiHbhQr6CoCo2V4p'; // different key
    const withMismatchedFragment = `did:key:${validMultibase}#${differentMultibase}`;

    expect(() => parseDidKeyVerificationMethod(withMismatchedFragment)).toThrow(
      'did:key verificationMethod fragment must equal body multibase'
    );
  });

  describe('signWitnessProofEntry', () => {
    const createWitnessedCandidate = async (controller: VerificationMethod, witness: VerificationMethod) => {
      const verifier = createTestVerifier(controller);
      const trusted = await createWitnessedTestDID({ controller, witness, verifier });
      const witnessProofs = [
        {
          versionId: trusted.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness),
              trusted.log[0].versionId,
              witnessVerificationMethod(witness)
            ),
          ],
        },
      ];
      const candidate = await updateDID({
        log: trusted.log,
        updated: nextSecond(trusted.log),
        signer: createTestSigner(controller),
        updateKeys: [controller.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(controller),
        verifier,
        witnessProofs,
      });

      return { candidate, trusted, verifier, witnessProofs };
    };

    // The table is built lazily because `initialDID` is created in `beforeAll`.
    test.each([
      {
        name: 'an empty trusted log',
        logs: () => ({ trustedLog: [], candidateLog: [initialDID.log[0], initialDID.log[0]] }),
      },
      {
        name: 'a non-empty trusted log',
        logs: () => ({ trustedLog: [initialDID.log[0]], candidateLog: [initialDID.log[0]] }),
      },
    ])('rejects a candidate without exactly one new entry over $name', async ({ logs }) => {
      await expect(
        signWitnessProofEntry({
          ...logs(),
          witnessSigner: createTestSigner(authKey),
          witnessProofs: [],
        })
      ).rejects.toThrow('candidateLog must contain exactly one entry more than trustedLog');
    });

    test('requires an explicit witness proof list and does not fetch remote proofs', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { candidate, trusted, verifier } = await createWitnessedCandidate(controller, witness);
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected network fetch'));

      try {
        await expect(
          signWitnessProofEntry({
            trustedLog: trusted.log,
            candidateLog: candidate.log,
            witnessSigner: createTestSigner(witness),
            verifier,
          } as unknown as Parameters<typeof signWitnessProofEntry>[0])
        ).rejects.toThrow('witnessProofs is required; pass [] for an empty witness list');
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    test('validates a candidate continuation and signs a proof the resolver accepts', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { candidate, trusted, verifier, witnessProofs } = await createWitnessedCandidate(controller, witness);
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected network fetch'));

      try {
        const witnessProof = await signWitnessProofEntry({
          trustedLog: trusted.log,
          candidateLog: candidate.log,
          witnessSigner: createTestSigner(witness),
          witnessProofs,
          verifier,
        });

        expect(witnessProof.versionId).toBe(candidate.log[1].versionId);
        expect(witnessProof.proof).toHaveLength(1);
        expect(witnessProof.proof[0].proofPurpose).toBe('assertionMethod');
        expect(fetchSpy).not.toHaveBeenCalled();

        const resolved = await resolveDIDFromLog(candidate.log, {
          verifier,
          witnessProofs: [...witnessProofs, witnessProof],
        });
        expect(resolved.meta.versionId).toBe(candidate.log[1].versionId);
        expect(resolved.meta.error).toBeUndefined();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    test('signs a genesis entry without enforcing its threshold', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { trusted, verifier } = await createWitnessedCandidate(controller, witness);

      const witnessProof = await signWitnessProofEntry({
        trustedLog: [],
        candidateLog: [trusted.log[0]],
        witnessSigner: createTestSigner(witness),
        witnessProofs: [],
        verifier,
      });

      expect(witnessProof.versionId).toBe(trusted.log[0].versionId);
      expect(witnessProof.proof).toHaveLength(1);
    });

    test('rejects a non-genesis entry supplied as the sole candidate entry when trustedLog is empty', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { candidate, verifier } = await createWitnessedCandidate(controller, witness);
      const standaloneSubsequentEntry = {
        ...candidate.log[1],
        parameters: { ...candidate.log[1].parameters, method: candidate.log[0].parameters.method },
      };

      await expect(
        signWitnessProofEntry({
          trustedLog: [],
          candidateLog: [standaloneSubsequentEntry],
          witnessSigner: createTestSigner(witness),
          witnessProofs: [],
          verifier,
        })
      ).rejects.toThrow("version '2' in log doesn't match expected '1'.");
    });

    test('enforces witness membership for genesis signing', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const unauthorized = await generateTestVerificationMethod();
      const { trusted, verifier } = await createWitnessedCandidate(controller, witness);

      await expect(
        signWitnessProofEntry({
          trustedLog: [],
          candidateLog: [trusted.log[0]],
          witnessSigner: createTestSigner(unauthorized),
          witnessProofs: [],
          verifier,
        })
      ).rejects.toThrow('not a member');
    });

    test('rejects a malformed genesis candidate', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { trusted, verifier } = await createWitnessedCandidate(controller, witness);
      const malformedGenesis = { ...trusted.log[0], state: { ...trusted.log[0].state, id: 'not-a-did' } };

      await expect(
        signWitnessProofEntry({
          trustedLog: [],
          candidateLog: [malformedGenesis],
          witnessSigner: createTestSigner(witness),
          witnessProofs: [],
          verifier,
        })
      ).rejects.toThrow();
    });

    test('rejects a candidate whose prefix tip does not match the trusted tip', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { candidate, trusted, verifier, witnessProofs } = await createWitnessedCandidate(controller, witness);
      const mismatchedTrustedLog = [{ ...trusted.log[0], versionId: '1-untrusted-tip' }];

      await expect(
        signWitnessProofEntry({
          trustedLog: mismatchedTrustedLog,
          candidateLog: candidate.log,
          witnessSigner: createTestSigner(witness),
          witnessProofs,
          verifier,
        })
      ).rejects.toThrow('Candidate log does not extend the trusted log tip');
    });

    test('rejects signing when prior witness proofs are missing', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { candidate, trusted, verifier } = await createWitnessedCandidate(controller, witness);
      const priorVersionId = trusted.log[trusted.log.length - 1].versionId;

      await expect(
        signWitnessProofEntry({
          trustedLog: trusted.log,
          candidateLog: candidate.log,
          witnessSigner: createTestSigner(witness),
          witnessProofs: [],
          verifier,
        })
      ).rejects.toThrow(`Witness threshold not met for version ${priorVersionId}: got 0, need 1`);
    });

    test('rejects a candidate with a broken hash chain', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { candidate, trusted, verifier, witnessProofs } = await createWitnessedCandidate(controller, witness);
      const tamperedCandidate = [
        candidate.log[0],
        { ...candidate.log[1], state: { ...candidate.log[1].state, alsoKnownAs: ['did:example:tampered'] } },
      ];

      await expect(
        signWitnessProofEntry({
          trustedLog: trusted.log,
          candidateLog: tamperedCandidate,
          witnessSigner: createTestSigner(witness),
          witnessProofs,
          verifier,
        })
      ).rejects.toThrow('Hash chain broken');
    });

    test('rejects a candidate tip with no active witness requirement', async () => {
      const controller = await generateTestVerificationMethod();
      const verifier = createTestVerifier(controller);
      const trusted = await createDID({
        address: 'example.com',
        signer: createTestSigner(controller),
        updateKeys: [controller.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(controller),
        verifier,
      });
      const candidate = await updateDID({
        log: trusted.log,
        updated: nextSecond(trusted.log),
        signer: createTestSigner(controller),
        updateKeys: [controller.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(controller),
        verifier,
      });

      await expect(
        signWitnessProofEntry({
          trustedLog: trusted.log,
          candidateLog: candidate.log,
          witnessSigner: createTestSigner(controller),
          witnessProofs: [],
          verifier,
        })
      ).rejects.toThrow('Candidate entry is not governed by an active witness requirement');
    });

    test('rejects a signer outside the governing witness list', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const unauthorized = await generateTestVerificationMethod();
      const { candidate, trusted, verifier, witnessProofs } = await createWitnessedCandidate(controller, witness);

      await expect(
        signWitnessProofEntry({
          trustedLog: trusted.log,
          candidateLog: candidate.log,
          witnessSigner: createTestSigner(unauthorized),
          witnessProofs,
          verifier,
        })
      ).rejects.toThrow('not a member');
    });

    test('rejects a malformed signer verification method', async () => {
      const controller = await generateTestVerificationMethod();
      const witness = await generateTestVerificationMethod();
      const { candidate, trusted, verifier, witnessProofs } = await createWitnessedCandidate(controller, witness);
      const validSigner = createTestSigner(witness);
      const malformedSigner: Signer = {
        sign: (input) => validSigner.sign(input),
        getVerificationMethodId: () => 'not-a-did-key',
      };

      await expect(
        signWitnessProofEntry({
          trustedLog: trusted.log,
          candidateLog: candidate.log,
          witnessSigner: malformedSigner,
          witnessProofs,
          verifier,
        })
      ).rejects.toThrow('Malformed did:key verificationMethod');
    });
  });

  test('Resolve requires witness threshold for each required entry', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      updated: nextSecond(didWithWitness.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    // A v1-only proof leaves v2 unwitnessed: cumulative approval runs backwards, so an
    // earlier proof never covers a later entry.
    await expect(
      resolveDIDFromLog(updatedDid.log, {
        verifier: testImplementation,
        witnessProofs: [
          {
            versionId: didWithWitness.log[0].versionId,
            proof: [
              await createWitnessProof(
                createWitnessSigner(witness1),
                didWithWitness.log[0].versionId,
                witnessVerificationMethod(witness1)
              ),
            ],
          },
        ],
      })
    ).rejects.toThrow(`Witness threshold not met for version ${updatedDid.log[1].versionId}`);
  });

  test('Resolve does not double-count duplicate proofs from the same witness DID', async () => {
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }],
      },
      verifier: testImplementation,
    });

    const versionId = didWithWitness.log[0].versionId;
    const duplicateProofsFromSameWitness = [
      await createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
      await createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
    ];

    await expect(
      resolveDIDFromLog(didWithWitness.log, {
        verifier: testImplementation,
        witnessProofs: [
          {
            versionId,
            proof: duplicateProofsFromSameWitness,
          },
        ],
      })
    ).rejects.toThrow(`Witness threshold not met for version ${versionId}`);
  });

  test('Resolve rejects a copied proofValue whose verificationMethod is swapped to another witness', async () => {
    // One genuine proof from witness1, plus a copy of it re-attributed to
    // witness2. The copy must be verified against witness2's own key (and
    // fail), not satisfied from the verification memo by its proofValue.
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }],
      },
      verifier: testImplementation,
    });

    const versionId = didWithWitness.log[0].versionId;
    const genuineProof = await createWitnessProof(
      createWitnessSigner(witness1),
      versionId,
      witnessVerificationMethod(witness1)
    );
    const reattributedProof = { ...genuineProof, verificationMethod: witnessVerificationMethod(witness2) };

    await expect(
      resolveDIDFromLog(didWithWitness.log, {
        verifier: testImplementation,
        witnessProofs: [{ versionId, proof: [genuineProof, reattributedProof] }],
      })
    ).rejects.toThrow(`Witness threshold not met for version ${versionId}`);
  });

  test('Resolve still counts a genuine proof after an invalid copy of it was verified first', async () => {
    // The invalid re-attributed copy is verified before the genuine proof; its
    // failure must not poison the verification memo for the genuine one.
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }],
      },
      verifier: testImplementation,
    });

    const versionId = didWithWitness.log[0].versionId;
    const genuineProof = await createWitnessProof(
      createWitnessSigner(witness1),
      versionId,
      witnessVerificationMethod(witness1)
    );
    const reattributedProof = { ...genuineProof, verificationMethod: witnessVerificationMethod(witness2) };

    const resolved = await resolveDIDFromLog(didWithWitness.log, {
      verifier: testImplementation,
      witnessProofs: [{ versionId, proof: [reattributedProof, genuineProof] }],
    });

    expect(resolved.did).toBe(didWithWitness.did);
  });

  test('Resolve rejects a log entry using the legacy witnesses/witnessThreshold parameters', async () => {
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Graft the legacy v0.5 shape onto the genesis parameters; fail closed
    // instead of resolving with the witness requirement silently ignored.
    const tamperedLog = structuredClone(created.log);
    (tamperedLog[0].parameters as Record<string, unknown>).witnesses = [
      { id: `did:key:${witness1.publicKeyMultibase}` },
    ];
    (tamperedLog[0].parameters as Record<string, unknown>).witnessThreshold = 1;

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      "Legacy 'witnesses'/'witnessThreshold' parameters are not supported"
    );
  });

  test('Resolve accepts later proof for earlier required entry', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      updated: nextSecond(didWithWitness.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    const resolved = await resolveDIDFromLog(updatedDid.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: updatedDid.log[1].versionId,
          proof: [
            // Published in version 2 while signing version 1 (later publication for earlier target).
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
            // Also satisfy the version 2 target check.
            await createWitnessProof(
              createWitnessSigner(witness1),
              updatedDid.log[1].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    expect(resolved.did).toBe(updatedDid.did);
  });

  test('Resolve accepts a single pruned later proof as cumulative approval for prior entries', async () => {
    // A pruned file (one proof at the latest versionId) must witness every earlier entry,
    // since a valid proof implies approval of all prior entries.
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      updated: nextSecond(didWithWitness.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    // Pruned file: only the latest proof, signing the LATEST versionId.
    const prunedWitnessProofs = [
      {
        versionId: updatedDid.log[1].versionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            updatedDid.log[1].versionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ];

    const resolved = await resolveDIDFromLog(updatedDid.log, {
      verifier: testImplementation,
      witnessProofs: prunedWitnessProofs,
    });

    expect(resolved.did).toBe(updatedDid.did);
    expect(resolved.meta?.error).toBeUndefined();
  });

  test('Resolve rejects a witness-list reduction approved only by the reduced list', async () => {
    // The reducing entry must still meet the previous list's threshold (the new list
    // activates only after publication).
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 2, witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }] },
      verifier: testImplementation,
    });

    const v1 = didWithWitness.log[0].versionId;
    const v1Proofs = {
      versionId: v1,
      proof: await Promise.all([
        createWitnessProof(createWitnessSigner(witness1), v1, witnessVerificationMethod(witness1)),
        createWitnessProof(createWitnessSigner(witness2), v1, witnessVerificationMethod(witness2)),
      ]),
    };

    // Reduce 2-of-2 to 1-of-1 (witness1 only).
    const reduced = await updateDID({
      log: didWithWitness.log,
      updated: nextSecond(didWithWitness.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid1 }] },
      verifier: testImplementation,
      witnessProofs: [v1Proofs],
    });

    const v2 = reduced.log[1].versionId;

    // Only witness1 (the reduced list) approves v2 -- insufficient for the old 2-of-2.
    await expect(
      resolveDIDFromLog(reduced.log, {
        verifier: testImplementation,
        witnessProofs: [
          v1Proofs,
          {
            versionId: v2,
            proof: [await createWitnessProof(createWitnessSigner(witness1), v2, witnessVerificationMethod(witness1))],
          },
        ],
      })
    ).rejects.toThrow(`Witness threshold not met for version ${v2}`);
  });

  test('Resolve ignores invalid witness proof if enough valid proofs remain', async () => {
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }],
      },
      verifier: testImplementation,
    });

    const resolved = await resolveDIDFromLog(didWithWitness.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            {
              ...(await createWitnessProof(
                createWitnessSigner(witness1),
                didWithWitness.log[0].versionId,
                witnessVerificationMethod(witness1)
              )),
              proofValue: 'zinvalid',
            },
            await createWitnessProof(
              createWitnessSigner(witness2),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness2)
            ),
          ],
        },
      ],
    });

    expect(resolved.did).toBe(didWithWitness.did);
  });

  test('Resolve maps witness threshold failure to invalidDid metadata for partial results', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      updated: nextSecond(didWithWitness.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    const resolved = await resolveDIDFromLog(updatedDid.log, {
      versionNumber: 1,
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    expect(resolved.meta.error).toBe('invalidDid');
    expect(resolved.meta.problemDetails).toBeDefined();
    expect(resolved.meta.problemDetails!.type).toBe(
      'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID'
    );
    expect(resolved.meta.problemDetails!.title).toBe('The resolved DID is invalid.');
    expect(resolved.meta.problemDetails!.detail).toContain('Witness threshold not met');
  });

  test('Update DID rejects duplicate witness IDs', async () => {
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const duplicateWitnessId = `did:key:${witness1.publicKeyMultibase}`;

    await expect(
      updateDID({
        log: noWitnessDID.log,
        updated: nextSecond(noWitnessDID.log),
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        witness: {
          threshold: 2,
          witnesses: [{ id: duplicateWitnessId }, { id: duplicateWitnessId }],
        },
        verifier: testImplementation,
      })
    ).rejects.toThrow(`Duplicate witness id: ${duplicateWitnessId}`);
  });

  test('Update DID normalizes empty witness list to inactive state', async () => {
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      updated: nextSecond(noWitnessDID.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 2,
        witnesses: [],
      },
      verifier: testImplementation,
    });

    expect(updatedDID.meta.witness).toEqual({});
    expect(updatedDID.log[1].parameters.witness).toEqual({});
  });

  test('Accept witness signer output containing undefined fields', async () => {
    const proof = await createWitnessProof(
      async () => ({
        proof: {
          created: undefined,
          proofValue: 'zInvalidButPresent',
        },
      }),
      initialDID.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    expect(proof.proofValue).toBe('zInvalidButPresent');
  });

  test('Reject witness signer output with no proof', async () => {
    await expect(
      createWitnessProof(
        async () => ({}) as unknown as { proof: { proofValue: string } },
        '1-test',
        witnessVerificationMethod(witness1)
      )
    ).rejects.toThrow('Witness proof is missing proofValue');
  });

  test('Reject witness signer output with a proof lacking proofValue', async () => {
    await expect(
      createWitnessProof(async () => ({ proof: {} }), '1-test', witnessVerificationMethod(witness1))
    ).rejects.toThrow('Witness proof is missing proofValue');
  });

  test('Default witness proof created timestamp is trimmed to whole seconds', async () => {
    const proof = await createWitnessProof(
      createWitnessSigner(witness1),
      '1-test',
      witnessVerificationMethod(witness1)
    );

    expect(proof.created).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  test('Deactivating a witnessed DID validates the prior log using caller-supplied witnessProofs', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const genesisDid = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const genesisVersionId = genesisDid.log[0].versionId;
    const genesisWitnessProofs = [
      {
        versionId: genesisVersionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            genesisVersionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ];

    // Deactivate: resolving the prior (witnessed) log must use the caller-supplied
    // proofs rather than falling back to a network fetch of did-witness.json.
    const deactivated = await deactivateDID({
      log: genesisDid.log,
      signer: createTestSigner(authKey),
      verifier: testImplementation,
      witnessProofs: genesisWitnessProofs,
    });

    expect(deactivated.meta.deactivated).toBe(true);
    expect(deactivated.log).toHaveLength(2);

    // The still-active genesis configuration also governs the deactivation entry
    // itself (v2); a proof signing the deactivation entry's own versionId cumulatively
    // satisfies both the genesis (v1) and deactivation (v2) requirements.
    const deactivationVersionId = deactivated.log[1].versionId;
    const cumulativeWitnessProofs = [
      {
        versionId: deactivationVersionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            deactivationVersionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ];

    const resolved = await resolveDIDFromLog(deactivated.log, {
      verifier: testImplementation,
      witnessProofs: cumulativeWitnessProofs,
    });
    expect(resolved.meta.deactivated).toBe(true);
    expect(resolved.meta.versionId).toBe(deactivationVersionId);
  });

  test('deactivateDID rejects when a witness is required but witnessProofs is explicitly empty', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const genesisDid = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch should not occur'));

    try {
      await expect(
        deactivateDID({
          log: genesisDid.log,
          signer: createTestSigner(authKey),
          verifier: testImplementation,
          witnessProofs: [],
        })
      ).rejects.toThrow();

      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  test('updateDID rejects when a witness is required but witnessProofs is explicitly empty', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const genesisDid = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch should not occur'));

    try {
      await expect(
        updateDID({
          log: genesisDid.log,
          signer: createTestSigner(authKey),
          updateKeys: [authKey.publicKeyMultibase!],
          verificationMethods: asPublicVerificationMethods(authKey),
          verifier: testImplementation,
          witnessProofs: [],
        })
      ).rejects.toThrow();

      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  test('updateDID fetches witness proofs when witnessProofs is omitted', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const genesisDid = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch observed'));

    try {
      await expect(
        updateDID({
          log: genesisDid.log,
          signer: createTestSigner(authKey),
          updateKeys: [authKey.publicKeyMultibase!],
          verificationMethods: asPublicVerificationMethods(authKey),
          verifier: testImplementation,
        })
      ).rejects.toThrow();

      expect(fetchSpy).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    } finally {
      fetchSpy.mockRestore();
    }
  });

  test('deactivateDID fetches witness proofs when witnessProofs is omitted', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const genesisDid = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch observed'));

    try {
      await expect(
        deactivateDID({
          log: genesisDid.log,
          signer: createTestSigner(authKey),
          verifier: testImplementation,
        })
      ).rejects.toThrow();

      expect(fetchSpy).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    } finally {
      fetchSpy.mockRestore();
    }
  });

  test('updateDID and deactivateDID never fetch witness proofs over the network when witnessProofs is supplied', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const genesisDid = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const genesisVersionId = genesisDid.log[0].versionId;
    const genesisWitnessProofs = [
      {
        versionId: genesisVersionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            genesisVersionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ];

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch should not occur'));

    try {
      const updatedDid = await updateDID({
        log: genesisDid.log,
        updated: nextSecond(genesisDid.log),
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
        witnessProofs: genesisWitnessProofs,
      });
      expect(fetchSpy).not.toHaveBeenCalled();

      const updatedVersionId = updatedDid.log[1].versionId;
      const updatedWitnessProofs = [
        {
          versionId: updatedVersionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              updatedVersionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ];

      await deactivateDID({
        log: updatedDid.log,
        signer: createTestSigner(authKey),
        verifier: testImplementation,
        witnessProofs: updatedWitnessProofs,
      });
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
