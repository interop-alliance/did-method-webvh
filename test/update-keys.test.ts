import { describe, expect, test, vi } from 'vitest';
import { documentStateIsValid } from '../src/assertions.js';
import { createDID, deactivateDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { deriveNextKeyHash } from '../src/utils/crypto.js';
import { MultibaseEncoding, multibaseEncode } from '../src/utils/multiformats.js';
import { defaultWebvhLogVerifier } from '../src/verifier.js';
import { resolveVM } from '../src/vm-resolver.js';
import { asPublicVerificationMethods, createTestSigner, generateTestVerificationMethod } from './utils.js';

const forms = ['multikey', 'did:key', 'verificationMethod'] as const;
type KeyForm = (typeof forms)[number];

const encodeKey = (key: string, form: KeyForm): string => {
  if (form === 'did:key') return `did:key:${key}`;
  if (form === 'verificationMethod') return `did:key:${key}#${key}`;
  return key;
};

describe('updateKeys input normalization', () => {
  test.each(forms)('createDID accepts %s and writes only multikeys', async (form) => {
    const key = await generateTestVerificationMethod();
    const signer = createTestSigner(key);
    const updateKeys = [
      form === 'verificationMethod' ? signer.getVerificationMethodId() : encodeKey(key.publicKeyMultibase!, form),
    ];
    const original = [...updateKeys];
    const options = Object.freeze({
      address: 'example.com',
      verifier: defaultWebvhLogVerifier,
      verificationMethods: asPublicVerificationMethods(key),
      signer,
      updateKeys,
    });
    Object.freeze(updateKeys);

    const result = await createDID(options);

    expect(result.log[0].parameters.updateKeys).toEqual([key.publicKeyMultibase]);
    expect(result.meta.updateKeys).toEqual([key.publicKeyMultibase]);
    expect(updateKeys).toEqual(original);
    await expect(resolveDIDFromLog(result.log)).resolves.toBeDefined();
  });

  for (const operation of [updateDID, deactivateDID]) {
    test.each(forms)(`${operation.name} normalizes %s before checking pre-rotation hashes`, async (form) => {
      const key = await generateTestVerificationMethod();
      const nextKey = await generateTestVerificationMethod();
      const { log } = await createDID({
        address: 'example.com',
        verifier: defaultWebvhLogVerifier,
        signer: createTestSigner(key),
        verificationMethods: asPublicVerificationMethods(key),
        updateKeys: [key.publicKeyMultibase!],
        nextKeyHashes: [await deriveNextKeyHash(nextKey.publicKeyMultibase!)],
      });
      const originalLog = JSON.stringify(log);
      const updateKeys = [encodeKey(nextKey.publicKeyMultibase!, form)];
      const originalKeys = [...updateKeys];
      Object.freeze(updateKeys);
      const result = await operation(
        Object.freeze({ log, verifier: defaultWebvhLogVerifier, signer: createTestSigner(nextKey), updateKeys })
      );

      expect(result.log[1].parameters.updateKeys).toEqual([nextKey.publicKeyMultibase]);
      expect(result.meta.updateKeys).toEqual([nextKey.publicKeyMultibase]);
      expect(updateKeys).toEqual(originalKeys);
      expect(JSON.stringify(log)).toBe(originalLog);
      await expect(resolveDIDFromLog(result.log)).resolves.toBeDefined();
    });
  }

  test('normalizes mixed forms without changing order', async () => {
    const keys = await Promise.all(forms.map(() => generateTestVerificationMethod()));
    const result = await createDID({
      address: 'example.com',
      verifier: defaultWebvhLogVerifier,
      signer: createTestSigner(keys[0]),
      verificationMethods: asPublicVerificationMethods(keys[0]),
      updateKeys: keys.map((key, index) => encodeKey(key.publicKeyMultibase!, forms[index])),
    });
    expect(result.meta.updateKeys).toEqual(keys.map((key) => key.publicKeyMultibase));
  });

  for (const operation of [createDID, updateDID, deactivateDID]) {
    test(`${operation.name} rejects invalid keys before signing, including unused keys`, async () => {
      const key = await generateTestVerificationMethod();
      const multikey = key.publicKeyMultibase!;
      const signer = createTestSigner(key);
      const { log } = await createDID({
        address: 'example.com',
        verifier: defaultWebvhLogVerifier,
        verificationMethods: asPublicVerificationMethods(key),
        signer,
        updateKeys: [multikey],
      });
      const sign = vi.spyOn(signer, 'sign');
      const wrongCodec = multibaseEncode(
        new Uint8Array([0xec, 0x01, ...new Uint8Array(32)]),
        MultibaseEncoding.BASE58_BTC
      );
      const invalidKeys = [
        '',
        'z0',
        '#key',
        'did:key:',
        `${multikey}#${multikey}`,
        `did:key:${multikey}#other`,
        `did:key:${multikey}/path`,
        `did:key:${multikey}?query`,
        wrongCodec,
        `did:key:${wrongCodec}`,
        `did:key:${wrongCodec}#${wrongCodec}`,
        multibaseEncode(new Uint8Array([0xed]), MultibaseEncoding.BASE58_BTC),
      ];

      for (const invalid of invalidKeys) {
        await expect(
          operation({
            address: 'example.com',
            verifier: defaultWebvhLogVerifier,
            log,
            signer,
            updateKeys: [multikey, invalid],
          })
        ).rejects.toThrow(/updateKeys\[1\]/);
      }
      expect(sign).not.toHaveBeenCalled();
    });
  }

  test('read-side authorization still requires bare multikeys', async () => {
    const key = await generateTestVerificationMethod();
    const { log } = await createDID({
      address: 'example.com',
      verifier: defaultWebvhLogVerifier,
      signer: createTestSigner(key),
      verificationMethods: asPublicVerificationMethods(key),
      updateKeys: [key.publicKeyMultibase!],
    });
    for (const form of ['did:key', 'verificationMethod'] as const) {
      await expect(
        documentStateIsValid(log[0], {
          updateKeys: [encodeKey(key.publicKeyMultibase!, form)],
          verifier: defaultWebvhLogVerifier,
          resolveVM,
        })
      ).rejects.toThrow('is not authorized to update');
    }
    await expect(
      documentStateIsValid(log[0], {
        updateKeys: [key.publicKeyMultibase!],
        verifier: defaultWebvhLogVerifier,
        resolveVM,
      })
    ).resolves.toBe(true);
  });
});
