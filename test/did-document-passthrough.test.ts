import { describe, expect, test } from 'vitest';
import { createDID, updateDID } from '../src/method.js';
import { generateParallelDidWeb } from '../src/utils.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
  nextSecond,
} from './utils.js';

describe('didDocument create pass-through', () => {
  test('warns and strips secretKeyMultibase when createDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();

    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    };

    try {
      const { doc } = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
      });

      expect(warnings.some((msg) => msg.includes('Removing secretKeyMultibase'))).toBe(true);
      expect((doc.verificationMethod ?? []).every((vm) => vm.secretKeyMultibase === undefined)).toBe(true);
    } finally {
      console.warn = originalWarn;
    }
  });

  test('creates DID from pass-through didDocument and replaces placeholders', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const { doc } = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: {
        id: '{DID}',
        '@context': ['https://www.w3.org/ns/did/v1'],
        service: [
          {
            id: '{DID}#service-1',
            type: 'LinkedDomains',
            serviceEndpoint: 'https://example.com',
          },
        ],
      },
    });

    expect(doc.id?.startsWith('did:webvh:')).toBe(true);
    expect(doc.service?.[0]?.id).toBe(`${doc.id}#service-1`);
  });

  test('rejects pass-through didDocument without placeholder in id', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: 'did:webvh:abc123:example.com',
        },
      })
    ).rejects.toThrow("didDocument.id must contain a '{SCID}' or '{DID}' placeholder");
  });

  test('adds derived alsoKnownAs aliases when flags are enabled', async () => {
    const authKey = await generateTestVerificationMethod();

    const { doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: {
        id: '{DID}',
        alsoKnownAs: ['did:example:existing'],
      },
      alsoKnownAsWeb: true,
    });

    expect(doc.alsoKnownAs).toContain('did:example:existing');
    expect(doc.alsoKnownAs).toContain('did:web:example.com');
  });

  test('throws when alsoKnownAs is not an array', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}',
          alsoKnownAs: 'did:example:not-array' as unknown as string[],
        },
        alsoKnownAsWeb: true,
      })
    ).rejects.toThrow('alsoKnownAs is not an array');
  });

  test('warns and strips secretKeyMultibase when updateDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    };

    try {
      const updated = await updateDID({
        log: created.log,
        updated: nextSecond(created.log),
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
      });

      expect(warnings.some((msg) => msg.includes('Removing secretKeyMultibase'))).toBe(true);
      expect((updated.doc.verificationMethod ?? []).every((vm) => vm.secretKeyMultibase === undefined)).toBe(true);
    } finally {
      console.warn = originalWarn;
    }
  });

  test('rejects pass-through didDocument whose substituted id does not match the created DID', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}garbage',
        },
      })
    ).rejects.toThrow(/must match expected DID/);
  });
});

describe('generateParallelDidWeb', () => {
  test('generates did:web doc with correct id', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.id).toBe('did:web:example.com');
  });

  test('adds full did:webvh DID to alsoKnownAs of did:web doc', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.alsoKnownAs).toContain(did);
  });

  test('returns webDoc on createDID when alsoKnownAsWeb is enabled', async () => {
    const authKey = await generateTestVerificationMethod();
    const result = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAsWeb: true,
    });

    expect(result.webDoc).toBeDefined();
    expect(result.webDoc?.id).toBe('did:web:example.com');
    expect(result.webDoc?.alsoKnownAs).toContain(result.did);
  });

  test('does not return webDoc on createDID when alsoKnownAsWeb is omitted', async () => {
    const authKey = await generateTestVerificationMethod();
    const result = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    expect(result.webDoc).toBeUndefined();
  });

  test('does not add implicit #files or #whois services', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);
    const services = webDoc.service ?? [];

    expect(services.some((service) => service.id?.endsWith('#files'))).toBe(false);
    expect(services.some((service) => service.id?.endsWith('#whois'))).toBe(false);
  });

  test('translates verification method ids and controllers to did:web', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    for (const verificationMethod of webDoc.verificationMethod ?? []) {
      expect(verificationMethod.id?.startsWith('did:web:')).toBe(true);
      expect(verificationMethod.controller?.startsWith('did:web:')).toBe(true);
    }
  });

  test('preserves path segments in generated did:web document', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      paths: ['path', 'sub'],
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.id).toBe('did:web:example.com:path:sub');
  });

  test('preserves encoded port in generated did:web document', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'https://example.com:8443/',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.id).toBe('did:web:example.com%3A8443');
  });

  test('does not include did:web self-reference in alsoKnownAs of did:web doc', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAsWeb: true,
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.alsoKnownAs).not.toContain('did:web:example.com');
    expect(webDoc.alsoKnownAs).toContain(did);
  });

  test('returns webDoc on updateDID when did:web alias is present', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAsWeb: true,
    });

    const updated = await updateDID({
      log: created.log,
      updated: nextSecond(created.log),
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAs: created.doc.alsoKnownAs,
    });

    expect(updated.webDoc).toBeDefined();
    expect(updated.webDoc?.id).toBe('did:web:example.com');
    expect(updated.webDoc?.alsoKnownAs).toContain(updated.did);
  });
});
