import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import type { DIDLog, FetchLike, VerificationMethod } from '../src/interfaces.js';
import { createDID, deactivateDID, resolveDID, updateDID } from '../src/method.js';
import * as resolutionModule from '../src/method_versions/method.v1.0.resolution.js';
import { fetchLogFromIdentifier, fetchWitnessProofs } from '../src/utils.js';
import { defaultWebvhLogVerifier } from '../src/verifier.js';
import { createResolveVM, resolveVM } from '../src/vm-resolver.js';
import { createWitnessProof } from '../src/witness.js';
import {
  asPublicVerificationMethods,
  createRoutedFetchMock,
  createTestSigner,
  createWitnessSigner,
  generateTestVerificationMethod,
  nextSecond,
  stubGlobalFetchUnused,
  TestCryptoImplementation,
  witnessVerificationMethod,
} from './utils.js';

const toJsonl = (log: DIDLog) => log.map((entry) => JSON.stringify(entry)).join('\n');

const createFetchMock = (body: string, init: { ok?: boolean; status?: number } = {}) =>
  vi.fn().mockResolvedValue({
    ok: init.ok ?? true,
    status: init.status ?? 200,
    text: async () => body,
    json: async () => JSON.parse(body),
  }) as unknown as ReturnType<typeof vi.fn> & FetchLike;

// Stub the global fetch with a single canned response, returning the mock so
// tests can assert on the requested URL.
const stubFetchResponse = (body: string, init: { ok?: boolean; status?: number } = {}) => {
  const fetchMock = createFetchMock(body, init);
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

  test('uses a custom fetch override when resolving a DID by identifier', async () => {
    stubGlobalFetchUnused();
    const customFetch = createFetchMock(toJsonl(log));

    const result = await resolveDID(did, { verifier, fetch: customFetch });

    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(result.didDocument?.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  test('resolves from a caller-supplied controlled DID log without fetching', async () => {
    const fetchMock = stubFetchResponse('');

    const result = await resolveDID(did, {
      verifier,
      resolveControlledDid: async (requestedDid) => {
        expect(requestedDid).toBe(did);
        return log;
      },
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.didDocument?.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  test('falls back to remote resolution when controlled DID lookup returns undefined', async () => {
    const fetchMock = stubFetchResponse(toJsonl(log));

    const result = await resolveDID(did, {
      verifier,
      resolveControlledDid: async () => undefined,
    });

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(result.didDocument?.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  test('maps controlled DID lookup failures to an internalError resolution result', async () => {
    const result = await resolveDID(did, {
      verifier,
      resolveControlledDid: async () => {
        throw new TypeError('fetch failed');
      },
    });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('internalError');
    expect(result.didResolutionMetadata.problemDetails?.detail).toContain('fetch failed');
  });

  test('rejects a caller-supplied log whose state.id does not match the requested DID', async () => {
    const didParts = did.split(':');
    const mismatchedDid = `${didParts.slice(0, 3).join(':')}:different-domain.example`;

    const result = await resolveDID(mismatchedDid, {
      verifier,
      resolveControlledDid: async () => log,
    });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.problemDetails?.detail).toMatch(/does not match state\.id/);
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

  test('uses a custom fetch override for DID log retrieval', async () => {
    const entries = [{ versionId: '1-abc' }, { versionId: '2-def' }];
    stubGlobalFetchUnused();
    const customFetch = createFetchMock(entries.map((entry) => JSON.stringify(entry)).join('\n'));

    const fetched = await fetchLogFromIdentifier('did:webvh:scid123:example.com:dids:issuer', customFetch);

    expect(customFetch).toHaveBeenCalledWith('https://example.com/dids/issuer/did.jsonl');
    expect(globalThis.fetch).not.toHaveBeenCalled();
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

  test('uses a custom fetch override for witness proof retrieval', async () => {
    const proofs = [{ versionId: '1-abc', proof: [] }];
    stubGlobalFetchUnused();
    const customFetch = createFetchMock(JSON.stringify(proofs));

    const result = await fetchWitnessProofs('did:webvh:scid123:example.com', customFetch);

    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(globalThis.fetch).not.toHaveBeenCalled();
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

describe('fetch override threading', () => {
  let authKey: VerificationMethod;
  let witnessKey: VerificationMethod;
  let verifier: TestCryptoImplementation;
  let did: string;
  let log: DIDLog;
  let witnessFile: string;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    witnessKey = await generateTestVerificationMethod();
    verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    ({ did, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: { threshold: 1, witnesses: [{ id: `did:key:${witnessKey.publicKeyMultibase}` }] },
      verifier,
    }));
    const proof = await createWitnessProof(
      createWitnessSigner(witnessKey),
      log[0].versionId,
      witnessVerificationMethod(witnessKey)
    );
    witnessFile = JSON.stringify([{ versionId: log[0].versionId, proof: [proof] }]);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  test('resolveDID retrieves did-witness.json through the fetch override', async () => {
    stubGlobalFetchUnused();
    const customFetch = createRoutedFetchMock({ 'did.jsonl': toJsonl(log), 'did-witness.json': witnessFile });

    const result = await resolveDID(did, { verifier, fetch: customFetch });

    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(did);
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('updateDID resolves the prior log with the fetch override', async () => {
    stubGlobalFetchUnused();
    const customFetch = createRoutedFetchMock({ 'did-witness.json': witnessFile });

    const updated = await updateDID({
      log,
      updated: nextSecond(log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
      fetch: customFetch,
    });

    expect(updated.log).toHaveLength(2);
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('deactivateDID resolves the prior log with the fetch override', async () => {
    stubGlobalFetchUnused();
    const customFetch = createRoutedFetchMock({ 'did-witness.json': witnessFile });

    const deactivated = await deactivateDID({
      log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier,
      fetch: customFetch,
    });

    expect(deactivated.meta.deactivated).toBe(true);
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('createResolveVM retrieves a did:webvh VM log through the fetch override', async () => {
    stubGlobalFetchUnused();
    const customFetch = createRoutedFetchMock({ 'did.jsonl': toJsonl(log), 'did-witness.json': witnessFile });
    const vmId = log[0].state.verificationMethod![0].id!;
    expect(vmId.startsWith(`${did}#`)).toBe(true);

    const resolved = await createResolveVM({ fetch: customFetch })(vmId);

    expect(resolved?.publicKeyMultibase).toBe(authKey.publicKeyMultibase);
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('createResolveVM consults resolveControlledDid before fetching the VM log', async () => {
    stubGlobalFetchUnused();
    const customFetch = createRoutedFetchMock({ 'did-witness.json': witnessFile });
    const resolveControlledDid = vi.fn(async (requested: string) => (requested === did ? log : undefined));
    const vmId = log[0].state.verificationMethod![0].id!;

    const resolved = await createResolveVM({ fetch: customFetch, resolveControlledDid })(vmId);

    expect(resolved?.publicKeyMultibase).toBe(authKey.publicKeyMultibase);
    expect(resolveControlledDid).toHaveBeenCalledWith(did);
    expect(customFetch).not.toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('createResolveVM falls back to fetching when resolveControlledDid returns undefined', async () => {
    stubGlobalFetchUnused();
    const customFetch = createRoutedFetchMock({ 'did.jsonl': toJsonl(log), 'did-witness.json': witnessFile });
    const resolveControlledDid = vi.fn(async () => undefined);
    const vmId = log[0].state.verificationMethod![0].id!;

    const resolved = await createResolveVM({ fetch: customFetch, resolveControlledDid })(vmId);

    expect(resolved?.publicKeyMultibase).toBe(authKey.publicKeyMultibase);
    expect(resolveControlledDid).toHaveBeenCalledWith(did);
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
