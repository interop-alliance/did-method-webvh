import { beforeAll, describe, expect, test } from 'vitest';
import type { CreateDIDResult, DIDLog, VerificationMethod } from '../src/interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import {
  getBaseUrl,
  getFileUrl,
  parseCanonicalAddress,
  parseDidWebvhIdentifier,
  requireDidDocumentId,
} from '../src/utils.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

describe('resolveDIDFromLog with verificationMethod', () => {
  let initialDID: CreateDIDResult;
  let fullLog: DIDLog;
  let authKey1: VerificationMethod,
    authKey2: VerificationMethod,
    keyAgreementKey: VerificationMethod,
    assertionKey: VerificationMethod;
  let testImplementation: TestCryptoImplementation;

  beforeAll(async () => {
    authKey1 = await generateTestVerificationMethod();
    authKey2 = await generateTestVerificationMethod();
    keyAgreementKey = await generateTestVerificationMethod();
    assertionKey = await generateTestVerificationMethod('assertionMethod', 'externallyDefinedId');
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey1 });

    // Create initial DID
    initialDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      created: '2023-01-01T00:00:00Z',
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier: testImplementation,
    });
    fullLog = initialDID.log;

    // Update DID to add a new authentication key
    const updateResult1 = await updateDID({
      log: fullLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1, authKey2),
      updated: '2023-02-01T00:00:01Z',
      verifier: testImplementation,
    });
    fullLog = updateResult1.log;

    // Update DID to add a keyAgreement key
    const updateResult2 = await updateDID({
      log: fullLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1, authKey2, keyAgreementKey),
      updated: '2023-03-01T00:00:02Z',
      verifier: testImplementation,
    });
    fullLog = updateResult2.log;

    // Update DID to add an assertion key
    const updateResult3 = await updateDID({
      log: fullLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1, authKey2, keyAgreementKey, assertionKey),
      updated: '2023-03-01T00:00:03Z',
      verifier: testImplementation,
    });
    fullLog = updateResult3.log;
  });

  test('Resolve DID with initial authentication key', async () => {
    const vmId = `${initialDID.did}#${authKey1.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDIDFromLog(fullLog, { verificationMethod: vmId, verifier: testImplementation });

    expect(doc!.verificationMethod!).toHaveLength(1);
    expect(doc!.verificationMethod![0].publicKeyMultibase).toBe(authKey1.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe('1');
  });

  test('Resolve DID with second authentication key', async () => {
    const vmId = `${initialDID.did}#${authKey2.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDIDFromLog(fullLog, { verificationMethod: vmId, verifier: testImplementation });

    expect(doc!.verificationMethod!).toHaveLength(2);
    expect(doc!.verificationMethod![1].publicKeyMultibase).toBe(authKey2.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe('2');
  });

  test('Resolve DID with keyAgreement key', async () => {
    const vmId = `${initialDID.did}#${keyAgreementKey.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDIDFromLog(fullLog, { verificationMethod: vmId, verifier: testImplementation });

    expect(doc!.verificationMethod!).toHaveLength(3);
    expect(doc!.verificationMethod![2].publicKeyMultibase).toBe(keyAgreementKey.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe('3');
  });

  test('Resolve DID with assertion authentication key (externally defined id)', async () => {
    const vmId = assertionKey.id!;
    const { doc, meta } = await resolveDIDFromLog(fullLog, { verificationMethod: vmId, verifier: testImplementation });

    expect(doc!.verificationMethod!).toHaveLength(4);
    expect(doc!.verificationMethod![3].publicKeyMultibase).toBe(assertionKey.publicKeyMultibase);
    expect(doc!.verificationMethod![3].id!.endsWith('externallyDefinedId')).toBe(true);
    expect(meta.versionId.split('-')[0]).toBe('4');
  });

  test('Resolve DID with non-existent verification method returns notFound', async () => {
    const vmId = `${initialDID.did}#non-existent-fragment`;

    const { doc, meta } = await resolveDIDFromLog(fullLog, { verificationMethod: vmId, verifier: testImplementation });

    expect(doc).toBeNull();
    expect(meta.error).toBe('notFound');
    expect(meta.problemDetails?.type).toBe('https://w3id.org/security#NOT_FOUND');
  });

  test('Resolve DID with verification method and version time', async () => {
    const vmId = `${initialDID.did}#${authKey2.publicKeyMultibase!.slice(-8)}`;
    const { doc, meta } = await resolveDIDFromLog(fullLog, {
      verificationMethod: vmId,
      versionTime: new Date('2023-02-15T00:00:00Z'),
      verifier: testImplementation,
    });

    expect(doc!.verificationMethod!).toHaveLength(2);
    expect(doc!.verificationMethod![1].publicKeyMultibase).toBe(authKey2.publicKeyMultibase);
    expect(meta.versionId.split('-')[0]).toBe('2');
  });

  test('Resolution result shares no state with the caller: mutating meta or doc leaves the log intact', async () => {
    const log = structuredClone(fullLog);
    const pristineLog = structuredClone(fullLog);

    const resolved = await resolveDIDFromLog(log, { verifier: testImplementation });

    resolved.meta.updateKeys.push('z6MkInjectedKey');
    resolved.meta.nextKeyHashes?.push('zInjectedHash');
    resolved.doc!.verificationMethod?.push({ id: `${resolved.did}#injected`, type: 'Multikey' });

    expect(log).toEqual(pristineLog);
  });

  test('Throw error when both verificationMethod and versionNumber are specified', async () => {
    const vmId = `${initialDID.did}#${authKey1.publicKeyMultibase!.slice(-8)}`;
    let error: Error | null = null;

    try {
      const resolved = await resolveDIDFromLog(fullLog, {
        verificationMethod: vmId,
        versionNumber: 2,
        verifier: testImplementation,
      });
      console.log('resolved', resolved);
    } catch (e) {
      error = e as Error;
    }
    expect(error).not.toBeNull();
    expect(error?.message).toBe('Cannot specify both verificationMethod and version number/id');
  });
});

describe('Resolver URL derivation', () => {
  test('Uses http for localhost DID host', () => {
    const did = 'did:webvh:scid:localhost%3A8000:test:path';
    expect(getBaseUrl(did)).toBe('http://localhost:8000/test/path');
    expect(getFileUrl(did)).toBe('http://localhost:8000/test/path/did.jsonl');
  });

  test('Uses https for non-localhost DID host', () => {
    const did = 'did:webvh:scid:example.com%3A8080:custom:path';
    expect(getBaseUrl(did)).toBe('https://example.com:8080/custom/path');
    expect(getFileUrl(did)).toBe('https://example.com:8080/custom/path/did.jsonl');
  });

  test('Uses .well-known did.jsonl when DID has no path', () => {
    const did = 'did:webvh:scid:example.com';
    expect(getBaseUrl(did)).toBe('https://example.com');
    expect(getFileUrl(did)).toBe('https://example.com/.well-known/did.jsonl');
  });

  test('Rejects DID identifier containing fragment or query contamination', () => {
    expect(() => getBaseUrl('did:webvh:scid:example.com#frag')).toThrow(
      'Address input must not include query or fragment components'
    );
    expect(() => getBaseUrl('did:webvh:scid:example.com?query=1')).toThrow(
      'Address input must not include query or fragment components'
    );
  });

  test('Rejects DID identifier containing traversal-style path segments', () => {
    expect(() => getBaseUrl('did:webvh:scid:example.com:..:secret')).toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
    expect(() => getBaseUrl('did:webvh:scid:example.com:%2E%2E:secret')).toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
    expect(() => getBaseUrl('did:webvh:scid:example.com:a%2Fb')).toThrow(
      'did:webvh identifier must not contain decoded slash within a single path segment'
    );
  });
});

describe('Direct utility guards and parsers', () => {
  test('requireDidDocumentId throws when id is missing', () => {
    expect(() => requireDidDocumentId(undefined)).toThrow('DID document id is missing');
    expect(() => requireDidDocumentId('')).toThrow('DID document id is missing');
  });

  test('requireDidDocumentId returns the provided id when present', () => {
    expect(requireDidDocumentId('did:webvh:scid:example.com')).toBe('did:webvh:scid:example.com');
  });

  test('parseCanonicalAddress rejects did:webvh with missing domain segment', () => {
    expect(() => parseCanonicalAddress('did:webvh:onlyscid')).toThrow(
      'Invalid did:webvh identifier: must contain SCID (or {SCID} placeholder) and domain'
    );
  });

  test('parseCanonicalAddress rejects malformed pre-encoded port separators', () => {
    expect(() => parseCanonicalAddress('example.com%3A8080%3A443')).toThrow('Invalid pre-encoded port separator');
  });

  test('parseCanonicalAddress rejects invalid host percent-encoding', () => {
    expect(() => parseCanonicalAddress('%E0%A4%A')).toThrow('Invalid percent-encoding in host: %E0%A4%A');
  });

  test('parseCanonicalAddress rejects IPv6-style hosts', () => {
    expect(() => parseCanonicalAddress('https://[::1]/')).toThrow('IP addresses are not allowed as hosts');
  });

  test('parseDidWebvhIdentifier rejects wrong method prefix', () => {
    // The method-specific prefix check runs first, so a non-webvh input is
    // rejected before any address parsing.
    expect(() => parseDidWebvhIdentifier('did:web:example.com', 'resolver input')).toThrow(
      'resolver input must be a valid did:webvh identifier'
    );
  });

  test('parseDidWebvhIdentifier rejects missing SCID segment', () => {
    expect(() => parseDidWebvhIdentifier('did:webvh::example.com', 'resolver input')).toThrow(
      'resolver input must include SCID segment'
    );
  });

  test('parseDidWebvhIdentifier returns parsed location and paths', () => {
    const parsed = parseDidWebvhIdentifier('did:webvh:scid123:example.com%3A8443:tenant:issuer', 'resolver input');

    expect(parsed).toEqual({
      scid: 'scid123',
      didDomainComponent: 'example.com%3A8443',
      paths: ['tenant', 'issuer'],
      locationKey: 'example.com%3A8443:tenant:issuer',
    });
  });
});
