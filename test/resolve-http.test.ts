import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import type { DIDLog, VerificationMethod } from '../src/interfaces.js';
import { createDID, resolveDID } from '../src/method.js';
import * as resolutionModule from '../src/method_versions/method.v1.0.resolution.js';
import { fetchLogFromIdentifier, fetchWitnessProofs } from '../src/utils.js';
import { defaultWebvhLogVerifier } from '../src/verifier.js';
import { resolveVM } from '../src/vm-resolver.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

const toJsonl = (log: DIDLog) => log.map((entry) => JSON.stringify(entry)).join('\n');

// Stub the global fetch with a single canned response, returning the mock so
// tests can assert on the requested URL.
const stubFetchResponse = (body: string, init: { ok?: boolean; status?: number } = {}) => {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: init.ok ?? true,
    status: init.status ?? 200,
    text: async () => body,
    json: async () => JSON.parse(body),
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
};

const silenceConsoleError = () => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
};

describe('resolveDID over HTTPS', () => {
  let authKey: VerificationMethod;
  let verifier: TestCryptoImplementation;
  let did: string;
  let log: DIDLog;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    ({ did, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  test('resolves a DID by fetching its log from the well-known URL', async () => {
    const fetchMock = stubFetchResponse(toJsonl(log));

    const result = await resolveDID(did, { verifier });

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(result.didDocument).toBeTruthy();
    expect(result.didDocument!.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.contentType).toBe('application/did+ld+json');
  });

  test('maps an HTTP 404 to the notFound resolution error', async () => {
    silenceConsoleError();
    stubFetchResponse('', { ok: false, status: 404 });

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didResolutionMetadata.problemDetails?.type).toBe('https://w3id.org/security#NOT_FOUND');
    expect(result.didResolutionMetadata.problemDetails?.detail).toContain('404');
  });

  test('maps an empty DID log to the notFound resolution error', async () => {
    silenceConsoleError();
    stubFetchResponse('  \n  ');

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
  });

  test('maps an invalid DID log to the invalidDid resolution error', async () => {
    stubFetchResponse(JSON.stringify({ not: 'a log entry' }));

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.problemDetails?.type).toBe(
      'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID'
    );
  });

  test('rejects a log whose SCID does not match the SCID in the DID', async () => {
    const didParts = did.split(':');
    didParts[2] = `${didParts[2].slice(0, -4)}zzzz`;
    const tamperedDid = didParts.join(':');
    stubFetchResponse(toJsonl(log));

    const result = await resolveDID(tamperedDid, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.problemDetails?.detail).toContain('does not match SCID');
  });

  test('maps a network failure to the internalError resolution error', async () => {
    silenceConsoleError();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('fetch failed')));

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('internalError');
  });
});

describe('fetchLogFromIdentifier', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test('fetches path-based DIDs from a path-qualified URL', async () => {
    const entries = [{ versionId: '1-abc' }, { versionId: '2-def' }];
    const fetchMock = stubFetchResponse(entries.map((entry) => JSON.stringify(entry)).join('\n'));

    const fetched = await fetchLogFromIdentifier('did:webvh:scid123:example.com:dids:issuer');

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/dids/issuer/did.jsonl');
    expect(fetched).toEqual(entries);
  });
});

describe('fetchWitnessProofs', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  test('fetches the witness proof file alongside the DID log', async () => {
    const proofs = [{ versionId: '1-abc', proof: [] }];
    const fetchMock = stubFetchResponse(JSON.stringify(proofs));

    const result = await fetchWitnessProofs('did:webvh:scid123:example.com');

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(result).toEqual(proofs);
  });

  test('returns an empty list when the witness proof file is missing', async () => {
    stubFetchResponse('', { ok: false, status: 404 });

    expect(await fetchWitnessProofs('did:webvh:scid123:example.com')).toEqual([]);
  });

  test('returns an empty list when fetching fails', async () => {
    silenceConsoleError();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connection refused')));

    expect(await fetchWitnessProofs('did:webvh:scid123:example.com')).toEqual([]);
  });
});

describe('resolveVM', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  test('resolves did:webvh VM via direct verificationMethod array match', async () => {
    const vmId = 'did:webvh:scid123:example.com#key-1';

    stubFetchResponse('{"versionId":"1-abc"}\n{"versionId":"2-def"}');
    const resolveV1LogSpy = vi.spyOn(resolutionModule, 'resolveV1Log').mockResolvedValue({
      did: 'did:webvh:scid123:example.com',
      doc: {
        id: 'did:webvh:scid123:example.com',
        verificationMethod: [
          {
            id: vmId,
            type: 'Multikey',
            publicKeyMultibase: 'z6Mkk6YgL8Lh6mLeW4x8pohWXmHfL6h4WQ7x8V8NwS6jQ2mZ',
          },
        ],
      },
      meta: {},
    } as unknown as Awaited<ReturnType<typeof resolutionModule.resolveV1Log>>);

    const resolved = await resolveVM(vmId);

    expect(resolved).toEqual({
      id: vmId,
      type: 'Multikey',
      publicKeyMultibase: 'z6Mkk6YgL8Lh6mLeW4x8pohWXmHfL6h4WQ7x8V8NwS6jQ2mZ',
    });
    // The nested log resolution must be able to verify entry proofs: without a
    // verifier every did:webvh VM resolution would fail unconditionally.
    expect(resolveV1LogSpy).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ verificationMethod: vmId, verifier: defaultWebvhLogVerifier })
    );
  });

  test('does not memoize did:webvh resolutions across calls, so key rotations are picked up', async () => {
    const vmId = 'did:webvh:scid123:example.com#key-1';

    const fetchMock = stubFetchResponse('{"versionId":"1-abc"}');
    vi.spyOn(resolutionModule, 'resolveV1Log').mockResolvedValue({
      did: 'did:webvh:scid123:example.com',
      doc: {
        id: 'did:webvh:scid123:example.com',
        verificationMethod: [{ id: vmId, type: 'Multikey', publicKeyMultibase: 'zSomeKey' }],
      },
      meta: {},
    } as unknown as Awaited<ReturnType<typeof resolutionModule.resolveV1Log>>);

    await resolveVM(vmId);
    await resolveVM(vmId);

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('resolves did:webvh VM via verification relationship object fallback', async () => {
    const vmId = 'did:webvh:scid123:example.com#assertion-key';

    stubFetchResponse('{"versionId":"1-abc"}\n{"versionId":"2-def"}');
    vi.spyOn(resolutionModule, 'resolveV1Log').mockResolvedValue({
      did: 'did:webvh:scid123:example.com',
      doc: {
        id: 'did:webvh:scid123:example.com',
        verificationMethod: [],
        assertionMethod: [
          'did:webvh:scid123:example.com#string-reference',
          {
            id: vmId,
            type: 'Multikey',
            publicKeyMultibase: 'z6MkoJ8mW6T2d4QF9xk33bQ4rQk6N4R8c6rj59YxQG3hbtVW',
          },
        ],
      },
      meta: {},
    } as unknown as Awaited<ReturnType<typeof resolutionModule.resolveV1Log>>);

    const resolved = await resolveVM(vmId);

    expect(resolved).toEqual({
      id: vmId,
      type: 'Multikey',
      publicKeyMultibase: 'z6MkoJ8mW6T2d4QF9xk33bQ4rQk6N4R8c6rj59YxQG3hbtVW',
    });
  });

  test('wraps unsupported verification method schemes', async () => {
    await expect(resolveVM('did:web:example.com#key-1')).rejects.toThrow(
      'Error resolving VM did:web:example.com#key-1'
    );
  });
});
