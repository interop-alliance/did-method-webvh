import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, test } from 'vitest';
import { signerFromExternalKey } from '../src/cryptography.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { MultibaseEncoding, multibaseEncode } from '../src/utils/multiformats.js';
import {
  convertWebvhIdToWebId,
  deriveNextKeyHash,
  getBaseUrl,
  getFileUrl,
  getHashCacheSizeForTests,
  HASH_CACHE_MAX_ENTRIES,
  logToJsonlString,
  readLogFromString,
} from '../src/utils.js';
import { asPublicVerificationMethods, createTestSigner, generateTestVerificationMethod, nextSecond } from './utils.js';

// R2 -- the core API defaults `verifier` to defaultWebvhLogVerifier, so a
// consumer never has to import from /driver or thread it through every call.
describe('R2: default verifier', () => {
  test('createDID + resolveDIDFromLog succeed with no verifier supplied', async () => {
    const authKey = await generateTestVerificationMethod();

    const { did, log } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const resolved = await resolveDIDFromLog(log);
    expect(resolved.did).toBe(did);
    expect(resolved.doc?.id).toBe(did);
    expect(resolved.meta.error).toBeUndefined();
  });
});

// R3 -- log and URL utilities are re-exported from the package so consumers do
// not reimplement the canonical mappings.
describe('R3: exported log and URL utilities', () => {
  test('readLogFromString / logToJsonlString round-trip', async () => {
    const authKey = await generateTestVerificationMethod();
    const { log } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const serialized = logToJsonlString(log);
    expect(serialized.endsWith('\n')).toBe(false);
    expect(readLogFromString(serialized)).toEqual(log);
  });

  test('readLogFromString tolerates a trailing newline', async () => {
    const authKey = await generateTestVerificationMethod();
    const { log } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    expect(readLogFromString(`${logToJsonlString(log)}\n`)).toEqual(log);
  });

  test('getBaseUrl / getFileUrl map a did:webvh id to its did.jsonl URL', () => {
    const did = 'did:webvh:QmScid:example.com';
    expect(getBaseUrl(did)).toBe('https://example.com');
    expect(getFileUrl(did)).toBe('https://example.com/.well-known/did.jsonl');

    const pathed = 'did:webvh:QmScid:example.com:user:alice';
    expect(getFileUrl(pathed)).toBe('https://example.com/user/alice/did.jsonl');
  });

  test('convertWebvhIdToWebId strips the SCID segment', () => {
    expect(convertWebvhIdToWebId('did:webvh:QmScid:example.com:user:alice')).toBe('did:web:example.com:user:alice');
  });
});

// R4 -- an external-key Signer factory, exercised with an in-memory
// @noble/curves Ed25519 key (the KMS/HSM signing shape).
describe('R4: signerFromExternalKey', () => {
  test('factory-built signer drives createDID and the result resolves', async () => {
    const secretKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(secretKey);
    const publicKeyMultibase = multibaseEncode(
      new Uint8Array([0xed, 0x01, ...publicKey]),
      MultibaseEncoding.BASE58_BTC
    );

    const signer = signerFromExternalKey({
      publicKeyMultibase,
      sign: async ({ data }) => ed25519.sign(data, secretKey),
    });

    expect(signer.getVerificationMethodId()).toBe(`did:key:${publicKeyMultibase}#${publicKeyMultibase}`);

    const { did, log } = await createDID({
      domain: 'example.com',
      signer,
      updateKeys: [publicKeyMultibase],
      verificationMethods: [{ type: 'Multikey', publicKeyMultibase, purpose: 'authentication' }],
    });

    const resolved = await resolveDIDFromLog(log);
    expect(resolved.did).toBe(did);
    expect(resolved.meta.error).toBeUndefined();
  });
});

// R5 -- verification-method id fragment ergonomics.
describe('R5: vmIdFragment option', () => {
  test("default 'short' uses the last 8 chars of the multibase", async () => {
    const authKey = await generateTestVerificationMethod();
    const { doc } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const fragment = doc.verificationMethod![0]!.id!.split('#')[1];
    expect(fragment).toBe(authKey.publicKeyMultibase!.slice(-8));
  });

  test("'multibase' emits a self-describing #<publicKeyMultibase> fragment", async () => {
    const authKey = await generateTestVerificationMethod();
    const { doc } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      vmIdFragment: 'multibase',
    });

    const vm = doc.verificationMethod![0]!;
    expect(vm.id!.split('#')[1]).toBe(authKey.publicKeyMultibase);
    // Relationship arrays reference the same full-multibase id.
    expect(doc.authentication![0]).toBe(vm.id);
  });
});

// R6 -- a key-only update preserves the prior entry's document.
describe('R6: sparse updateDID preserves the prior document', () => {
  test('updateDID with only updateKeys + nextKeyHashes keeps the VM set intact', async () => {
    const authKey = await generateTestVerificationMethod();
    const vm2 = await generateTestVerificationMethod('assertionMethod');
    const vm3 = await generateTestVerificationMethod('keyAgreement');

    const { doc: createdDoc, log } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey, vm2, vm3),
    });
    expect(createdDoc.verificationMethod).toHaveLength(3);

    const rotatedKey = await generateTestVerificationMethod();
    const { doc: updatedDoc } = await updateDID({
      log,
      updated: nextSecond(log),
      signer: createTestSigner(authKey),
      updateKeys: [rotatedKey.publicKeyMultibase!],
      nextKeyHashes: [await deriveNextKeyHash(rotatedKey.publicKeyMultibase!)],
    });

    // No document directives were supplied, so every verification-method field
    // is carried forward from entry 1 unchanged.
    expect(updatedDoc.verificationMethod).toEqual(createdDoc.verificationMethod);
    expect(updatedDoc.authentication).toEqual(createdDoc.authentication);
    expect(updatedDoc.assertionMethod).toEqual(createdDoc.assertionMethod);
    expect(updatedDoc.keyAgreement).toEqual(createdDoc.keyAgreement);
  });
});

// R8 -- the deriveHash memo cache is bounded.
describe('R8: bounded deriveHash cache', () => {
  test('cache size stays within the cap under many distinct inputs', async () => {
    const { deriveHash } = await import('../src/utils.js');
    for (let i = 0; i < HASH_CACHE_MAX_ENTRIES * 2 + 50; i++) {
      await deriveHash({ marker: 'R8-cache-bound', i });
    }
    expect(getHashCacheSizeForTests()).toBeLessThanOrEqual(HASH_CACHE_MAX_ENTRIES);
  });
});
