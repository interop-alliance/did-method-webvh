import { describe, expect, test } from 'vitest';
import { BASE_CONTEXT } from '../src/constants.js';
import {
  createDIDDoc,
  createVMID,
  enrichAlsoKnownAs,
  findVerificationMethod,
  generateParallelDidWeb,
  normalizeVMs,
  validateCreateDidDocument,
} from '../src/did-document.js';
import type { DIDDoc, VerificationMethod } from '../src/interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
  nextSecond,
} from './utils.js';

describe('didDocument create pass-through', () => {
  test('rejects secretKeyMultibase when createDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
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

  test('rejects private key material in pass-through didDocument', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}',
          verificationMethod: [
            {
              id: '#key-1',
              type: 'Multikey',
              controller: '{DID}',
              publicKeyMultibase: authKey.publicKeyMultibase,
              secretKeyMultibase: authKey.secretKeyMultibase,
            },
          ],
        },
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });

  test('rejects nested private key material in pass-through didDocument', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}',
          verificationMethod: [
            {
              id: '#key-1',
              type: 'ConditionalProof2022',
              controller: '{DID}',
              conditionOr: [
                {
                  id: '#nested-key',
                  type: 'Multikey',
                  controller: '{DID}',
                  publicKeyMultibase: authKey.publicKeyMultibase,
                  secretKeyMultibase: authKey.secretKeyMultibase,
                },
              ],
            } as unknown as VerificationMethod,
          ],
        },
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
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

  test('rejects secretKeyMultibase when updateDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    await expect(
      updateDID({
        log: created.log,
        updated: nextSecond(created.log),
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });

  test('rejects nested secretKeyMultibase in createDID verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [
          {
            id: '#key-1',
            type: 'ConditionalProof2022',
            conditionOr: [
              {
                id: '#nested-key',
                type: 'Multikey',
                publicKeyMultibase: authKey.publicKeyMultibase,
                secretKeyMultibase: authKey.secretKeyMultibase,
              },
            ],
          } as unknown as VerificationMethod,
        ],
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });

  test('rejects nested secretKeyMultibase in updateDID verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    await expect(
      updateDID({
        log: created.log,
        updated: nextSecond(created.log),
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        verificationMethods: [
          {
            id: '#key-1',
            type: 'ConditionalProof2022',
            conditionOr: [
              {
                id: '#nested-key',
                type: 'Multikey',
                publicKeyMultibase: authKey.publicKeyMultibase,
                secretKeyMultibase: authKey.secretKeyMultibase,
              },
            ],
          } as unknown as VerificationMethod,
        ],
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });

  test('createDID refuses didDocument combined with an option that replaces part of it', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: { id: '{DID}' },
        verificationMethods: asPublicVerificationMethods(authKey),
        context: ['https://www.w3.org/ns/did/v1'],
      })
    ).rejects.toThrow(/didDocument replaces the whole document and cannot be combined with .*verificationMethods/);
  });

  test('createDID accepts didDocument together with alsoKnownAsWeb', async () => {
    const authKey = await generateTestVerificationMethod();

    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: { id: '{DID}', '@context': [...BASE_CONTEXT] },
      alsoKnownAsWeb: true,
    });

    expect(doc.alsoKnownAs).toEqual([`did:web:${did.split(':').slice(3).join(':')}`]);
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

  test('returns webDoc on updateDID when alsoKnownAsWeb is enabled', async () => {
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
      alsoKnownAsWeb: true,
    });

    expect(updated.webDoc).toBeDefined();
    expect(updated.webDoc?.id).toBe('did:web:example.com');
    expect(updated.webDoc?.alsoKnownAs).toContain(updated.did);
  });

  test('warns on updateDID when the document carries the did:web alias but alsoKnownAsWeb is omitted', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAsWeb: true,
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
        verificationMethods: asPublicVerificationMethods(authKey),
        alsoKnownAs: created.doc.alsoKnownAs,
      });

      expect(updated.webDoc).toBeUndefined();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings.some((message) => message.includes('alsoKnownAsWeb was not passed'))).toBe(true);
  });
});

describe('did-document helper branches', () => {
  test('validateCreateDidDocument rejects non-object and non-string id', () => {
    expect(() => validateCreateDidDocument(null as unknown as DIDDoc)).toThrow('didDocument must be an object');
    expect(() => validateCreateDidDocument({ id: 123 } as unknown as DIDDoc)).toThrow(
      "didDocument 'id' field must be a string"
    );
  });

  test('enrichAlsoKnownAs rejects invalid did:webvh identifier when alias flag is enabled', () => {
    expect(() => enrichAlsoKnownAs({ id: '{DID}' } as DIDDoc, 'did:example:123', { alsoKnownAsWeb: true })).toThrow(
      "Invalid did:webvh id 'did:example:123'"
    );
  });

  test('createVMID falls back to random suffix when publicKeyMultibase is missing', () => {
    const vm: VerificationMethod = {
      id: '#temporary',
      type: 'Multikey',
    };

    const vmId = createVMID(vm, 'did:webvh:zQmExample:example.com');
    expect(vmId).toMatch(/^did:webvh:zQmExample:example.com#[a-z0-9]{8}$/);
  });

  test('normalizeVMs defaults a vm without purpose into authentication only', () => {
    const did = 'did:webvh:zQmExample:example.com';
    const normalized = normalizeVMs(
      [
        {
          type: 'Multikey',
          publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        },
      ],
      did
    );

    expect(normalized.verificationMethod).toHaveLength(1);
    expect(normalized.authentication).toHaveLength(1);
    expect(normalized.assertionMethod).toEqual([]);
  });

  test('normalizeVMs emits a vm id once per relationship even when purpose repeats it', () => {
    const did = 'did:webvh:zQmExample:example.com';
    const normalized = normalizeVMs(
      [
        {
          type: 'Multikey',
          publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          purpose: ['authentication', 'authentication', 'assertionMethod'],
        },
      ],
      did
    );

    // A duplicate relationship reference would be an invalid document and
    // would shift the genesis hash (SCID) for the same input.
    expect(normalized.authentication).toHaveLength(1);
    expect(normalized.assertionMethod).toHaveLength(1);
  });

  test('normalizeVMs relationship entries reuse the materialized id for a vm with no id or publicKeyMultibase', () => {
    const did = 'did:webvh:zQmExample:example.com';
    const normalized = normalizeVMs(
      [
        // Neither `id` nor `publicKeyMultibase`: the id is materialized from a
        // random fragment. Relationship entries must reference that exact id, not
        // a second, independently generated random id.
        { type: 'Multikey' } as VerificationMethod,
      ],
      did
    );

    expect(normalized.verificationMethod).toHaveLength(1);
    const materializedId = normalized.verificationMethod[0].id;
    expect(materializedId?.startsWith(`${did}#`)).toBe(true);
    // Absent purpose defaults into authentication; the ref must match exactly.
    expect(normalized.authentication).toEqual([materializedId]);
  });

  test('findVerificationMethod resolves from relationship object and returns null when not found', () => {
    const vm: VerificationMethod = {
      id: '#rel-vm',
      type: 'Multikey',
      publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    };

    const doc: DIDDoc = {
      id: 'did:webvh:zQmExample:example.com',
      authentication: [vm as unknown as string],
    };

    expect(findVerificationMethod(doc, '#rel-vm')).toEqual(vm);
    expect(findVerificationMethod(doc, '#missing')).toBeNull();
  });

  test('createDIDDoc propagates a populated relationship field and omits empty ones', async () => {
    const assertionVmId = 'did:webvh:zQmExample:example.com#assertion-key-1';

    const doc = createDIDDoc({
      did: 'did:webvh:zQmExample:example.com',
      verificationMethods: [
        {
          id: assertionVmId,
          type: 'Multikey',
          publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          purpose: 'assertionMethod',
        },
      ],
      authentication: [],
      keyAgreement: [],
      alsoKnownAs: [],
    });

    expect(doc.assertionMethod).toEqual([assertionVmId]);
    expect(doc.verificationMethod).toHaveLength(1);
    // Empty relationship arrays are omitted rather than emitted as `[]`.
    expect(doc.authentication).toBeUndefined();
    expect(doc.keyAgreement).toBeUndefined();
    expect(doc.alsoKnownAs).toBeUndefined();
    expect('capabilityInvocation' in doc).toBe(false);
  });
});

describe('@context options', () => {
  const extraContext = 'https://w3id.org/byoe';

  const createOptions = async (authKey: VerificationMethod) => ({
    address: 'example.com',
    signer: createTestSigner(authKey),
    verifier: createTestVerifier(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
  });

  test('createDID with additionalContext appends after the base pair', async () => {
    const authKey = await generateTestVerificationMethod();

    const { doc } = await createDID({
      ...(await createOptions(authKey)),
      additionalContext: [extraContext],
    });

    expect(doc['@context']).toEqual([...BASE_CONTEXT, extraContext]);
  });

  test('createDID with additionalContext matches the equivalent context override byte for byte', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = '2024-01-01T00:00:00Z';

    const { doc: appended } = await createDID({
      ...(await createOptions(authKey)),
      created,
      additionalContext: [extraContext],
    });
    const { doc: overridden } = await createDID({
      ...(await createOptions(authKey)),
      created,
      context: [...BASE_CONTEXT, extraContext],
    });

    expect(JSON.stringify(appended)).toEqual(JSON.stringify(overridden));
  });

  test('createDID with a supplied didDocument appends to that document context', async () => {
    const authKey = await generateTestVerificationMethod();

    // `didDocument` cannot be combined with `verificationMethods`, so this
    // does not reuse `createOptions`.
    const { doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:webvh:{SCID}:example.com',
      },
      additionalContext: [extraContext],
    });

    expect(doc['@context']).toEqual(['https://www.w3.org/ns/did/v1', extraContext]);
  });

  test('createDID refuses context together with additionalContext', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        ...(await createOptions(authKey)),
        context: [...BASE_CONTEXT],
        additionalContext: [extraContext],
      })
    ).rejects.toThrow(/not both/);
  });

  test('updateDID appends additionalContext after the carried-forward context, deduplicated', async () => {
    const authKey = await generateTestVerificationMethod();
    const { log } = await createDID({
      ...(await createOptions(authKey)),
      additionalContext: [extraContext],
    });

    const { doc: updated, log: updatedLog } = await updateDID({
      log,
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updated: nextSecond(log),
      additionalContext: ['https://example.com/other/v1'],
    });

    expect(updated['@context']).toEqual([...BASE_CONTEXT, extraContext, 'https://example.com/other/v1']);

    // Re-adding an entry already present is a no-op.
    const { doc: redundant } = await updateDID({
      log: updatedLog,
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updated: nextSecond(updatedLog),
      additionalContext: [extraContext],
    });

    expect(redundant['@context']).toEqual([...BASE_CONTEXT, extraContext, 'https://example.com/other/v1']);
  });

  test('updateDID with context replaces the prior context wholesale', async () => {
    const authKey = await generateTestVerificationMethod();
    const { log } = await createDID({
      ...(await createOptions(authKey)),
      additionalContext: [extraContext],
    });

    const { doc } = await updateDID({
      log,
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updated: nextSecond(log),
      context: ['https://www.w3.org/ns/did/v1'],
    });

    expect(doc['@context']).toEqual(['https://www.w3.org/ns/did/v1']);
  });

  test('updateDID with neither option preserves the prior context', async () => {
    const authKey = await generateTestVerificationMethod();
    const { log } = await createDID({
      ...(await createOptions(authKey)),
      additionalContext: [extraContext],
    });

    const { doc } = await updateDID({
      log,
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updated: nextSecond(log),
    });

    expect(doc['@context']).toEqual([...BASE_CONTEXT, extraContext]);
  });

  test('updateDID refuses context together with additionalContext', async () => {
    const authKey = await generateTestVerificationMethod();
    const { log } = await createDID(await createOptions(authKey));

    await expect(
      updateDID({
        log,
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updated: nextSecond(log),
        context: [...BASE_CONTEXT],
        additionalContext: [extraContext],
      })
    ).rejects.toThrow(/not both/);
  });
});

describe('complete didDocument contract and update semantics', () => {
  test('creates DID with multi-relationship verification method and relative ids', async () => {
    const authKey = await generateTestVerificationMethod();

    const didDocument: DIDDoc = {
      '@context': [...BASE_CONTEXT],
      id: '{DID}',
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
      ],
      authentication: ['#key-1'],
      assertionMethod: ['#key-1'],
      keyAgreement: ['#key-1'],
    };

    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase as string],
      didDocument,
    });

    expect(doc.id).toBe(did);
    expect(doc.verificationMethod?.[0].id).toBe('#key-1');
    expect(doc.verificationMethod?.[0].controller).toBe(did);
    expect(doc.authentication).toEqual(['#key-1']);
    expect(doc.assertionMethod).toEqual(['#key-1']);
    expect(doc.keyAgreement).toEqual(['#key-1']);
    // A top-level controller that was omitted stays omitted.
    expect(doc.controller).toBeUndefined();
  });

  test('preserves a caller-authored top-level controller that differs from the subject DID', async () => {
    const authKey = await generateTestVerificationMethod();

    const { doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase as string],
      didDocument: {
        '@context': [...BASE_CONTEXT],
        id: '{DID}',
        controller: 'did:example:external-controller',
        verificationMethod: [
          {
            id: '#key-1',
            type: 'Multikey',
            controller: '{DID}',
            publicKeyMultibase: authKey.publicKeyMultibase,
          },
        ],
        authentication: ['#key-1'],
      },
    });

    expect(doc.controller).toBe('did:example:external-controller');
  });

  test('rejects an authored verification method missing an explicit controller', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase as string],
        didDocument: {
          '@context': [...BASE_CONTEXT],
          id: '{DID}',
          verificationMethod: [
            {
              id: '#key-1',
              type: 'Multikey',
              publicKeyMultibase: authKey.publicKeyMultibase,
            },
          ],
          authentication: ['#key-1'],
        },
      })
    ).rejects.toThrow(/must have an explicit string 'controller'/);
  });

  test('rejects an authored verification method missing an id', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase as string],
        didDocument: {
          '@context': [...BASE_CONTEXT],
          id: '{DID}',
          verificationMethod: [
            {
              type: 'Multikey',
              controller: '{DID}',
              publicKeyMultibase: authKey.publicKeyMultibase,
            },
          ],
        },
      })
    ).rejects.toThrow(/must have a non-empty string 'id'/);
  });

  test('a DID created from a {DID}-authored document resolves', async () => {
    const authKey = await generateTestVerificationMethod();
    const { log, did } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase as string],
      didDocument: {
        '@context': [...BASE_CONTEXT],
        id: '{DID}',
        verificationMethod: [
          {
            id: '{DID}#key-1',
            type: 'Multikey',
            controller: '{DID}',
            publicKeyMultibase: authKey.publicKeyMultibase,
          },
        ],
        authentication: ['{DID}#key-1'],
      },
    });

    // Resolution rebuilds the genesis preimage by substituting the SCID back to
    // `{SCID}` only, so `{DID}` has to have been substituted before the entry
    // was hashed or the SCID check fails.
    const resolved = await resolveDIDFromLog(log, { verifier: createTestVerifier(authKey) });
    expect(resolved.did).toBe(did);
  });

  test('derives the same SCID whether the document is authored with {DID} or did:webvh:{SCID}:host', async () => {
    const authKey = await generateTestVerificationMethod();
    const baseOptions = {
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase as string],
      created: '2024-01-01T00:00:00Z',
    };
    const authoredDoc = (subject: string): DIDDoc => ({
      '@context': [...BASE_CONTEXT],
      id: subject,
      verificationMethod: [
        {
          id: `${subject}#key-1`,
          type: 'Multikey',
          controller: subject,
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
      ],
      authentication: [`${subject}#key-1`],
    });

    const viaDidPlaceholder = await createDID({ ...baseOptions, didDocument: authoredDoc('{DID}') });
    const viaScidPlaceholder = await createDID({
      ...baseOptions,
      didDocument: authoredDoc('did:webvh:{SCID}:example.com'),
    });

    // `{DID}` is substituted before SCID derivation, so both spellings of the
    // same authored document hash identically.
    expect(viaDidPlaceholder.did).toBe(viaScidPlaceholder.did);
  });

  test('update with a complete didDocument replaces state outright, deleting an omitted service', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase as string],
      didDocument: {
        '@context': [...BASE_CONTEXT],
        id: '{DID}',
        verificationMethod: [
          {
            id: '#key-1',
            type: 'Multikey',
            controller: '{DID}',
            publicKeyMultibase: authKey.publicKeyMultibase,
          },
        ],
        authentication: ['#key-1'],
        service: [{ id: '#service-1', type: 'LinkedDomains', serviceEndpoint: 'https://example.com' }],
      },
    });

    expect(created.doc.service).toHaveLength(1);

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      updated: nextSecond(created.log),
      didDocument: {
        '@context': [...BASE_CONTEXT],
        id: created.did,
        verificationMethod: [
          {
            id: '#key-1',
            type: 'Multikey',
            controller: created.did,
            publicKeyMultibase: authKey.publicKeyMultibase,
          },
        ],
        authentication: ['#key-1'],
      },
    });

    expect(updated.doc.service).toBeUndefined();
    expect(updated.doc.authentication).toEqual(['#key-1']);
  });

  test('update rejects a didDocument whose id does not match the DID', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase as string],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    await expect(
      updateDID({
        log: created.log,
        signer,
        verifier,
        updated: nextSecond(created.log),
        didDocument: { '@context': [...BASE_CONTEXT], id: 'did:example:someone-else' },
      })
    ).rejects.toThrow(/Updated DID document id must match expected DID/);
  });

  test('update rejects a didDocument with no id', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    await expect(
      updateDID({
        log: created.log,
        signer,
        verifier,
        updated: nextSecond(created.log),
        didDocument: { '@context': [...BASE_CONTEXT] },
      })
    ).rejects.toThrow("didDocument 'id' field must be a string");
  });

  test('a portable move accepts an authored document still naming the old DID and rewrites it', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      portable: true,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      updated: nextSecond(created.log),
      address: 'new-domain.com',
      didDocument: {
        '@context': [...BASE_CONTEXT],
        id: created.did,
        verificationMethod: [
          {
            id: `${created.did}#key-1`,
            type: 'Multikey',
            controller: created.did,
            publicKeyMultibase: authKey.publicKeyMultibase,
          },
        ],
        authentication: [`${created.did}#key-1`],
      },
    });

    expect(updated.did).toContain('new-domain.com');
    expect(updated.doc.id).toBe(updated.did);
    expect(updated.doc.verificationMethod?.[0].id).toBe(`${updated.did}#key-1`);
    expect(updated.doc.verificationMethod?.[0].controller).toBe(updated.did);
    expect(updated.doc.authentication).toEqual([`${updated.did}#key-1`]);
  });

  test('a portable move rejects an authored document naming a third DID', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      portable: true,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    await expect(
      updateDID({
        log: created.log,
        signer,
        verifier,
        updated: nextSecond(created.log),
        address: 'new-domain.com',
        didDocument: { '@context': [...BASE_CONTEXT], id: 'did:example:someone-else' },
      })
    ).rejects.toThrow(/Updated DID document id must match expected DID/);
  });

  test('update appends additionalContext to an authored didDocument', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      updated: nextSecond(created.log),
      didDocument: { '@context': [...BASE_CONTEXT], id: created.did },
      additionalContext: ['https://example.com/extra/v1'],
    });

    expect(updated.doc['@context']).toEqual([...BASE_CONTEXT, 'https://example.com/extra/v1']);
  });

  test('update refuses didDocument combined with an overlay option', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase as string],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    await expect(
      updateDID({
        log: created.log,
        signer,
        verifier,
        updated: nextSecond(created.log),
        didDocument: { '@context': [...BASE_CONTEXT], id: created.did },
        services: [{ id: '#service-1', type: 'LinkedDomains', serviceEndpoint: 'https://example.com' }],
      })
    ).rejects.toThrow(/cannot be combined with services/);
  });

  test('update without didDocument preserves prior state while updating parameters', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const authKey2 = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey1);
    const verifier = createTestVerifier(authKey1);

    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey1.publicKeyMultibase as string],
      didDocument: {
        '@context': [...BASE_CONTEXT],
        id: '{DID}',
        verificationMethod: [
          {
            id: '#key-1',
            type: 'Multikey',
            controller: '{DID}',
            publicKeyMultibase: authKey1.publicKeyMultibase,
          },
        ],
        authentication: ['#key-1'],
        service: [{ id: '#service-1', type: 'LinkedDomains', serviceEndpoint: 'https://example.com' }],
      },
    });

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      updated: nextSecond(created.log),
      updateKeys: [authKey2.publicKeyMultibase as string],
    });

    expect(updated.meta.updateKeys).toEqual([authKey2.publicKeyMultibase as string]);
    expect(updated.doc.service).toEqual(created.doc.service);
    expect(updated.doc.authentication).toEqual(['#key-1']);
    expect(updated.doc.verificationMethod).toEqual(created.doc.verificationMethod);
  });

  test('a parameters-only update preserves an external top-level controller', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase as string],
      didDocument: {
        '@context': [...BASE_CONTEXT],
        id: '{DID}',
        controller: 'did:example:external-controller',
        verificationMethod: [
          {
            id: '#key-1',
            type: 'Multikey',
            controller: '{DID}',
            publicKeyMultibase: authKey.publicKeyMultibase,
          },
        ],
        authentication: ['#key-1'],
      },
    });

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      updated: nextSecond(created.log),
      nextKeyHashes: [],
    });

    expect(updated.doc.controller).toBe('did:example:external-controller');
  });
});
