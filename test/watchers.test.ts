import { describe, expect, test } from 'vitest';
import { METHOD, PLACEHOLDER } from '../src/constants.js';
import { createDataIntegrityProofTemplate } from '../src/cryptography.js';
import { createDIDDoc, replaceCreateDidPlaceholders } from '../src/did-document.js';
import type { DIDLog } from '../src/interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { deriveHash } from '../src/utils/crypto.js';
import { buildVersionId } from '../src/utils.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  nextSecond,
  TestCryptoImplementation,
} from './utils.js';

describe('Watcher Handling', () => {
  test('Create DID with watchers', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const { log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers,
      verifier,
    });

    const resolved = await resolveDIDFromLog(log, { verifier });
    expect(resolved.meta.watchers).toEqual(watchers);
  });

  test('Watchers persist across updates when not specified', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const initial = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers,
      verifier,
    });

    const updated = await updateDID({
      log: initial.log,
      updated: nextSecond(initial.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    const resolved = await resolveDIDFromLog(updated.log, { verifier });
    expect(resolved.meta.watchers).toEqual(watchers);
  });

  test('Disable watchers with null', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const initial = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers,
      verifier,
    });

    const updated = await updateDID({
      log: initial.log,
      updated: nextSecond(initial.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers: null,
      verifier,
    });

    const resolved = await resolveDIDFromLog(updated.log, { verifier });
    expect(updated.log[1].parameters.watchers).toEqual([]);
    expect(Array.isArray(resolved.meta.watchers)).toBe(true);
    expect(resolved.meta.watchers).toEqual([]);
  });

  test.each([
    ['omitted', 'omit' as const],
    ['null', null],
  ])('Resolves watchers as [] when the genesis entry has watchers %s', async (_label, watchers) => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const signer = createTestSigner(authKey);
    const created = new Date().toISOString();
    const placeholderDid = `did:${METHOD}:${PLACEHOLDER}:example.com`;
    const entry: DIDLog[0] = {
      versionId: PLACEHOLDER,
      versionTime: created,
      parameters: {
        method: `did:${METHOD}:1.0`,
        scid: PLACEHOLDER,
        updateKeys: [authKey.publicKeyMultibase!],
        portable: false,
        nextKeyHashes: [],
        witness: {},
        deactivated: false,
        ...(watchers === 'omit' ? {} : { watchers }),
      },
      state: createDIDDoc({ did: placeholderDid, verificationMethods: asPublicVerificationMethods(authKey) }),
    };
    const scid = await deriveHash(entry);
    const did = `did:${METHOD}:${scid}:example.com`;
    const genesis = replaceCreateDidPlaceholders(entry, scid, did);
    genesis.versionId = buildVersionId(1, await deriveHash(genesis));
    const template = createDataIntegrityProofTemplate({
      verificationMethod: signer.getVerificationMethodId(),
      created,
      proofPurpose: 'assertionMethod',
    });
    const signed = await signer.sign({ document: genesis, proof: template });
    genesis.proof = [{ ...template, proofValue: signed.proofValue }];

    expect(genesis.parameters.watchers).toEqual(watchers === 'omit' ? undefined : null);
    const resolved = await resolveDIDFromLog([genesis], { verifier });
    expect(resolved.meta.watchers).toEqual([]);
  });
});
