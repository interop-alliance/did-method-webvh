import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import { isDIDResolutionError } from '@interop/data-integrity-core';
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import type { FetchLike, VerificationMethod } from '../src/interfaces.js';
import { deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { WitnessThresholdError } from '../src/method_versions/method.v1.0.resolution.js';
import { mapErrorToCode } from '../src/resolver-result.js';
import { fetchLogFromIdentifier, fetchWitnessProofs } from '../src/utils.js';
import { createResolveVM } from '../src/vm-resolver.js';
import {
  appendRawLogEntry,
  createTestDID,
  createTestSigner,
  createWitnessedTestDID,
  generateTestVerificationMethod,
  MOCK_SCID,
  stubGlobalFetchUnused,
  TestCryptoImplementation,
} from './utils.js';

const DID = `did:webvh:${MOCK_SCID}:example.com`;

describe("network: 'none'", () => {
  let authKey: VerificationMethod;
  let verifier: TestCryptoImplementation;
  let witnessed: Awaited<ReturnType<typeof createWitnessedTestDID>>;
  let fetchSpy: ReturnType<typeof vi.fn>;
  let globalFetch: ReturnType<typeof vi.fn>;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    witnessed = await createWitnessedTestDID({ controller: authKey, verifier });
  });

  const stubFetches = () => {
    fetchSpy = vi.fn().mockRejectedValue(new Error('fetch override should not be called'));
    globalFetch = stubGlobalFetchUnused();
    return fetchSpy as unknown as FetchLike;
  };

  const expectNothingFetched = () => {
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(globalFetch).not.toHaveBeenCalled();
  };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const proofsNotFound = (did: string) =>
    `Witness proofs not found for ${did}: network is 'none', so they were not fetched; supply witnessProofs`;

  test('resolveDIDFromLog reports witness proofs it may not fetch as not found', async () => {
    const fetch = stubFetches();

    const error = await resolveDIDFromLog(witnessed.log, { verifier, network: 'none', fetch }).catch((e) => e);

    expect(error.message).toBe(proofsNotFound(witnessed.did));
    expect(isDIDResolutionError(error)).toBe(true);
    expect(error).not.toBeInstanceOf(WitnessThresholdError);
    expect(mapErrorToCode(error)).toBe('notFound');
    expectNothingFetched();
  });

  test('a historical selector does not turn the missing witness proofs into a decorated snapshot', async () => {
    const fetch = stubFetches();

    await expect(
      resolveDIDFromLog(witnessed.log, { verifier, network: 'none', fetch, versionNumber: 1 })
    ).rejects.toThrow(proofsNotFound(witnessed.did));
    expectNothingFetched();
  });

  test('resolveDID reports notFound for the witness proofs of a controlled log without fetching', async () => {
    const fetch = stubFetches();

    const result = await resolveDID(witnessed.did, {
      verifier,
      network: 'none',
      fetch,
      resolveControlledDid: async () => witnessed.log,
    });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didResolutionMetadata.message).toBe(proofsNotFound(witnessed.did));
    expectNothingFetched();
  });

  test('resolveDID reports notFound for a log it would have to fetch', async () => {
    const fetch = stubFetches();

    const result = await resolveDID(witnessed.did, { verifier, network: 'none', fetch });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expectNothingFetched();
  });

  test('updateDID and deactivateDID do not fetch while resolving the prior log', async () => {
    const fetch = stubFetches();
    const signer = createTestSigner(authKey);

    await expect(updateDID({ log: witnessed.log, signer, verifier, network: 'none', fetch })).rejects.toThrow(
      proofsNotFound(witnessed.did)
    );
    await expect(deactivateDID({ log: witnessed.log, signer, verifier, network: 'none', fetch })).rejects.toThrow(
      proofsNotFound(witnessed.did)
    );
    expectNothingFetched();
  });

  test('createResolveVM does not fetch a did:webvh verification method log', async () => {
    const fetch = stubFetches();

    await expect(createResolveVM({ network: 'none', fetch })(`${DID}#key-1`)).rejects.toThrow(
      `Error resolving VM ${DID}#key-1`
    );
    expectNothingFetched();
  });

  test('supplied witnessProofs are still used with no network access', async () => {
    const fetch = stubFetches();

    await expect(
      resolveDIDFromLog(witnessed.log, { verifier, network: 'none', fetch, witnessProofs: [] })
    ).rejects.toThrow('Witness threshold not met');
    expectNothingFetched();
  });
});

describe('fetchWitnessProofs bounds', () => {
  const proofs = [{ versionId: '1-abc', proof: [] }];
  const encode = (text: string) => new TextEncoder().encode(text);

  test('refuses redirects and passes an abort signal', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(proofs)));

    expect(await fetchWitnessProofs(DID, fetchMock as unknown as FetchLike)).toEqual(proofs);

    expect(fetchMock).toHaveBeenCalledWith(
      'https://example.com/.well-known/did-witness.json',
      expect.objectContaining({ redirect: 'error', signal: expect.any(AbortSignal) })
    );
  });

  test('does not follow a redirect with the global fetch', async () => {
    const requested: string[] = [];
    const server = createServer((request, response) => {
      requested.push(request.url ?? '');
      if (request.url === '/.well-known/did-witness.json') {
        response.writeHead(302, { location: '/elsewhere.json' }).end();
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(proofs));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    try {
      const error = await fetchWitnessProofs(`did:webvh:${MOCK_SCID}:localhost%3A${port}`).catch((e) => e);

      expect(error).toBeInstanceOf(Error);
      expect(requested).toEqual(['/.well-known/did-witness.json']);
      expect(mapErrorToCode(error)).toBe('internalError');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  test('times out a request that never answers and aborts it', async () => {
    let signal: AbortSignal | undefined;
    const hanging: FetchLike = (_url, init) => {
      signal = init?.signal ?? undefined;
      return new Promise(() => {});
    };

    const error = await fetchWitnessProofs(DID, hanging, { timeoutMs: 20 }).catch((e) => e);

    expect(error.message).toMatch(/did-witness\.json timed out after 20 ms/);
    expect(signal?.aborted).toBe(true);
    expect(mapErrorToCode(error)).toBe('internalError');
  });

  test('times out a body that never finishes', async () => {
    const stalled: FetchLike = async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(encode('['));
          },
        })
      );

    await expect(fetchWitnessProofs(DID, stalled, { timeoutMs: 20 })).rejects.toThrow('timed out after 20 ms');
  });

  test('rejects a declared content-length over the limit without reading the body', async () => {
    const text = vi.fn(async () => '[]');
    let cancelled = false;
    const oversized: FetchLike = async () => ({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-length': '1000' }),
      body: new ReadableStream({
        cancel() {
          cancelled = true;
        },
      }),
      text,
      json: async () => [],
    });

    const error = await fetchWitnessProofs(DID, oversized, { maxBytes: 100 }).catch((e) => e);

    expect(error.message).toContain('exceeds the 100 byte limit');
    expect(text).not.toHaveBeenCalled();
    expect(cancelled).toBe(true);
    expect(mapErrorToCode(error)).toBe('internalError');
  });

  test('stops reading a streamed body once it passes the limit', async () => {
    let chunksServed = 0;
    let cancelled = false;
    const endless: FetchLike = async () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            chunksServed++;
            controller.enqueue(encode(' '.repeat(64)));
          },
          cancel() {
            cancelled = true;
          },
        })
      );

    await expect(fetchWitnessProofs(DID, endless, { maxBytes: 100 })).rejects.toThrow('exceeds the 100 byte limit');
    expect(cancelled).toBe(true);
    expect(chunksServed).toBeLessThan(10);
  });

  test('measures the body of a response that has no stream', async () => {
    const body = JSON.stringify([{ versionId: '1-abc', proof: [], padding: 'x'.repeat(200) }]);
    const adapter: FetchLike = async () => ({
      ok: true,
      status: 200,
      text: async () => body,
      json: async () => JSON.parse(body),
    });

    await expect(fetchWitnessProofs(DID, adapter, { maxBytes: 100 })).rejects.toThrow('exceeds the 100 byte limit');
    expect(await fetchWitnessProofs(DID, adapter, { maxBytes: 1000 })).toHaveLength(1);
  });

  test('accepts a streamed body within the limit', async () => {
    const within: FetchLike = async () => new Response(JSON.stringify(proofs));

    expect(await fetchWitnessProofs(DID, within, { maxBytes: 1000 })).toEqual(proofs);
  });
});

describe('fetch adapters without WHATWG headers or body', () => {
  const proofs = [{ versionId: '1-abc', proof: [] }];

  test('reads a Node stream body with plain-object headers through text()', async () => {
    const body = JSON.stringify(proofs);
    const adapter: FetchLike = async () => ({
      ok: true,
      status: 200,
      headers: { 'content-length': String(body.length) },
      body: Readable.from([body]),
      text: async () => body,
      json: async () => proofs,
    });

    expect(await fetchWitnessProofs(DID, adapter)).toEqual(proofs);
    await expect(fetchWitnessProofs(DID, adapter, { maxBytes: 5 })).rejects.toThrow('exceeds the 5 byte limit');
  });

  test('returns [] for a 404 witness file from such an adapter', async () => {
    const adapter: FetchLike = async () => ({
      ok: false,
      status: 404,
      headers: {},
      body: Readable.from(['not found']),
      text: async () => 'not found',
      json: async () => ({}),
    });

    expect(await fetchWitnessProofs(DID, adapter)).toEqual([]);
  });
});

describe('redirects reported by a custom fetch', () => {
  const proofs = [{ versionId: '1-abc', proof: [] }];
  const respond = (extra: Record<string, unknown>): FetchLike =>
    (async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(proofs),
      json: async () => proofs,
      ...extra,
    })) as unknown as FetchLike;

  test('refuses a response with redirected: true', async () => {
    const error = await fetchWitnessProofs(DID, respond({ redirected: true })).catch((e) => e);

    expect(error.message).toBe(
      'Request to https://example.com/.well-known/did-witness.json was redirected; redirects are refused'
    );
    expect(mapErrorToCode(error)).toBe('internalError');
  });

  test('refuses a response whose url is not the requested one', async () => {
    const error = await fetchWitnessProofs(DID, respond({ url: 'https://elsewhere.example/did-witness.json' })).catch(
      (e) => e
    );

    expect(error.message).toContain('was redirected');
    expect(mapErrorToCode(error)).toBe('internalError');
  });

  test('accepts a response whose url is the requested one, or empty', async () => {
    const url = 'https://example.com/.well-known/did-witness.json';
    expect(await fetchWitnessProofs(DID, respond({ url, redirected: false }))).toEqual(proofs);
    expect(await fetchWitnessProofs(DID, respond({ url: '' }))).toEqual(proofs);
  });
});

describe('deadline with a custom fetch that ignores init', () => {
  test('cancels the body reader so the read loop stops', async () => {
    let cancelled = false;
    const stalled: FetchLike = async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('['));
          },
          cancel() {
            cancelled = true;
          },
        })
      );

    const error = await fetchWitnessProofs(DID, stalled, { timeoutMs: 20 }).catch((e) => e);

    expect(error.message).toContain('timed out after 20 ms');
    expect(cancelled).toBe(true);
  });
});

describe('fetchLogFromIdentifier bounds', () => {
  const logUrl = 'https://example.com/.well-known/did.jsonl';

  test('passes redirect: error and an abort signal', async () => {
    const fetchMock = vi.fn(async () => new Response('{"versionId":"1-abc"}'));

    await fetchLogFromIdentifier(DID, fetchMock as unknown as FetchLike);

    expect(fetchMock).toHaveBeenCalledWith(
      logUrl,
      expect.objectContaining({ redirect: 'error', signal: expect.any(AbortSignal) })
    );
  });

  test('times out a log request that never answers', async () => {
    const hanging: FetchLike = () => new Promise(() => {});

    const error = await fetchLogFromIdentifier(DID, hanging, { timeoutMs: 20 }).catch((e) => e);

    expect(error.message).toBe(`Request to ${logUrl} timed out after 20 ms`);
    expect(mapErrorToCode(error)).toBe('internalError');
  });

  test('rejects a log body over the size limit', async () => {
    const large: FetchLike = async () => new Response('x'.repeat(200));

    const error = await fetchLogFromIdentifier(DID, large, { maxBytes: 100 }).catch((e) => e);

    expect(error.message).toBe(`Response body at ${logUrl} exceeds the 100 byte limit`);
    expect(mapErrorToCode(error)).toBe('internalError');
  });

  test('classifies HTTP statuses and an empty log by code', async () => {
    const status =
      (code: number): FetchLike =>
      async () =>
        new Response('', { status: code });

    expect(mapErrorToCode(await fetchLogFromIdentifier(DID, status(404)).catch((e) => e))).toBe('notFound');
    expect(mapErrorToCode(await fetchLogFromIdentifier(DID, status(500)).catch((e) => e))).toBe('internalError');
    expect(mapErrorToCode(await fetchLogFromIdentifier(DID, status(200)).catch((e) => e))).toBe('notFound');
  });

  test('wraps an error thrown by fetch as internalError with the original as cause', async () => {
    const original = new TypeError('fetch failed');
    const failing: FetchLike = async () => {
      throw original;
    };

    const error = await fetchLogFromIdentifier(DID, failing).catch((e) => e);

    expect(isDIDResolutionError(error)).toBe(true);
    expect(error.code).toBe('internalError');
    expect(error.cause).toBe(original);
    expect(error.message).toBe(`Request to ${logUrl} failed: fetch failed`);
  });

  test('resolveDID reports a failed fetch as internalError', async () => {
    const failing: FetchLike = async () => {
      throw new TypeError('fetch failed');
    };

    const result = await resolveDID(DID, { fetch: failing });

    expect(result.didResolutionMetadata.error).toBe('internalError');
    expect(result.didResolutionMetadata.message).toContain('fetch failed');
  });
});

describe('the witness file URL', () => {
  test('replaces only the trailing file name of the log URL', async () => {
    const fetchMock = vi.fn(async (_url: string) => new Response('[]'));
    const fetch = fetchMock as unknown as FetchLike;

    await fetchWitnessProofs(`did:webvh:${MOCK_SCID}:did.jsonl.example.com`, fetch);
    await fetchWitnessProofs(`did:webvh:${MOCK_SCID}:did.jsonl.example.com:did.jsonl:issuer`, fetch);

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'https://did.jsonl.example.com/.well-known/did-witness.json',
      'https://did.jsonl.example.com/did.jsonl/issuer/did-witness.json',
    ]);
  });
});

describe('error classification ignores text taken from the log', () => {
  const resolveTampered = async (parameters: Record<string, unknown>) => {
    const { did, log, signer, verifier } = await createTestDID();
    const tampered = await appendRawLogEntry({ log, signer, parameters });
    return resolveDID(did, { verifier, witnessProofs: [], resolveControlledDid: async () => tampered });
  };

  test.each([
    ['a parameter key that reads as a 404', { 'HTTP error! status: 404': true }, 'HTTP error! status: 404'],
    ['a parameter key that reads as a timeout', { 'timed out after 1 ms': true }, 'timed out after 1 ms'],
    [
      'a witness threshold that reads as a missing log',
      { witness: { threshold: 'DID log not found' } },
      'DID log not found',
    ],
  ])('%s maps to invalidDid', async (_name, parameters, injected) => {
    const result = await resolveTampered(parameters);

    expect(result.didResolutionMetadata.message).toContain(injected);
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
  });
});
