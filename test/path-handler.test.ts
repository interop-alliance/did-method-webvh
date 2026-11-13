import { afterEach, beforeAll, describe, expect, test } from 'vitest';
import type { DIDLog, ServiceEndpoint, Verifier } from '../src/interfaces.js';
import { createDID, deactivateDID, dereference, resolveDID, updateDID } from '../src/method.js';
import { parseDidUrl, pathHandlerUrl, selectPathHandler } from '../src/path-handler.js';
import { createWitnessProof } from '../src/witness.js';
import {
  asPublicVerificationMethods,
  createRoutedFetchMock,
  createTestSigner,
  createTestVerifier,
  createWitnessSigner,
  generateTestVerificationMethod,
  MOCK_SCID,
  nextSecond,
  stubGlobalFetchUnused,
  witnessVerificationMethod,
} from './utils.js';

const DID = `did:webvh:${MOCK_SCID}:example.com`;
const PATH_HANDLER = 'PathHandler';
const storage: ServiceEndpoint = {
  type: PATH_HANDLER,
  path: '/',
  serviceEndpoint: 'https://provider.example/storage/',
};
const images: ServiceEndpoint = { type: PATH_HANDLER, path: '/images', serviceEndpoint: 'https://cdn.example/img' };

describe('parseDidUrl', () => {
  test('splits DID, path, version selector, and fragment', () => {
    expect(parseDidUrl(`${DID}/images/logo.png?versionId=2-xyz#top`)).toEqual({
      did: DID,
      path: '/images/logo.png',
      versionId: '2-xyz',
      fragment: 'top',
    });
  });

  test('a bare DID has an empty path and no fragment', () => {
    expect(parseDidUrl(DID)).toStrictEqual({ did: DID, path: '' });
  });

  test('keeps the DID path segments of the identifier out of the DID URL path', () => {
    expect(parseDidUrl(`${DID}:api:v1/whois`)).toStrictEqual({ did: `${DID}:api:v1`, path: '/whois' });
  });

  test('only the selectors the URL carries are present on the result', () => {
    expect(parseDidUrl(`${DID}/a?versionNumber=3`)).toStrictEqual({ did: DID, path: '/a', versionNumber: 3 });
  });

  test('an empty fragment is treated as none', () => {
    expect(parseDidUrl(`${DID}/a#`)).toStrictEqual({ did: DID, path: '/a' });
  });

  test.each([
    '2025-01-02T03:04:05Z',
    '2025-01-02T03:04:05.250Z',
    '2025-01-02T03:04:05+00:00',
    '2025-01-02T03%3A04%3A05%2B00%3A00',
  ])('parses versionTime %s as a strict UTC ISO 8601 datetime', (versionTime) => {
    expect(parseDidUrl(`${DID}/a?versionTime=${versionTime}`).versionTime).toEqual(
      new Date(decodeURIComponent(versionTime))
    );
  });

  test.each([
    [`${DID}/a?`, /Empty query/],
    [`${DID}/a?service=files`, /Unsupported DID parameter 'service'/],
    [`${DID}/a?versionId=1-a&versionId=2-b`, /Repeated DID parameter 'versionId'/],
    [`${DID}/a?versionId=`, /Empty DID parameter 'versionId'/],
    [`${DID}/a?versionId`, /Empty DID parameter 'versionId'/],
    [`${DID}/a?versionNumber=0`, /positive integer/],
    [`${DID}/a?versionNumber=two`, /positive integer/],
    [`${DID}/a?versionNumber=99999999999999999999`, /positive integer/],
    [`${DID}/a?versionTime=yesterday`, /UTC ISO8601/],
    [`${DID}/a?versionTime=2025`, /UTC ISO8601/],
    [`${DID}/a?versionTime=1/2/2025`, /UTC ISO8601/],
    [`${DID}/a?versionTime=2025-01-02T03:04:05`, /UTC ISO8601/],
    [`${DID}/a?versionTime=2025-02-30T03:04:05Z`, /UTC ISO8601/],
    [`${DID}/a?versionTime=2025-01-02T04:04:05+01:00`, /must be in UTC/],
    [`${DID}/a?versionId=%E0%A4%A`, /Malformed percent-encoding/],
    [`${DID}/a?%E0=1`, /Malformed percent-encoding/],
  ])('rejects %s', (didUrl, error) => {
    expect(() => parseDidUrl(didUrl)).toThrow(error);
  });

  test('every parser error names the DID URL', () => {
    const didUrl = `${DID}/a?versionId=%E0%A4%A`;
    expect(() => parseDidUrl(didUrl)).toThrow(didUrl);
  });

  test('a narrowed parameter set reports other selectors as unsupported before reading their value', () => {
    expect(() => parseDidUrl(`${DID}?versionTime=garbage`, ['versionId'])).toThrow(
      /Unsupported DID parameter 'versionTime'/
    );
    expect(parseDidUrl(`${DID}?versionId=1-a`, ['versionId'])).toStrictEqual({ did: DID, versionId: '1-a', path: '' });
  });
});

describe('selectPathHandler', () => {
  const url = (doc: { service?: ServiceEndpoint[] }, path: string) => {
    const selection = selectPathHandler(doc, path);
    return selection && pathHandlerUrl(selection);
  };

  test('returns undefined when the document has no matching PathHandler', () => {
    expect(selectPathHandler({}, '/governance/issuers.json')).toBeUndefined();
    expect(
      selectPathHandler({ service: [{ type: 'LinkedDomains', serviceEndpoint: 'https://x' }] }, '/a')
    ).toBeUndefined();
    expect(selectPathHandler({ service: [images] }, '/whois')).toBeUndefined();
  });

  test('the longest complete match wins', () => {
    const doc = { service: [storage, images] };
    expect(url(doc, '/images/logo.png')).toBe('https://cdn.example/img/logo.png');
    expect(url(doc, '/images')).toBe('https://cdn.example/img');
    expect(url(doc, '/imagesx')).toBe('https://provider.example/storage/imagesx');
    expect(url(doc, '/docs/readme')).toBe('https://provider.example/storage/docs/readme');
  });

  test('a trailing slash on the service path does not change what it matches', () => {
    const slashed: ServiceEndpoint = {
      type: PATH_HANDLER,
      path: '/images/',
      serviceEndpoint: 'https://cdn.example/img/',
    };
    const doc = { service: [storage, slashed] };
    expect(url(doc, '/images/logo.png')).toBe('https://cdn.example/img/logo.png');
    expect(url(doc, '/images')).toBe('https://cdn.example/img/');
    expect(url(doc, '/imagesx')).toBe('https://provider.example/storage/imagesx');
  });

  test('ignores a service whose path is not a string starting with /', () => {
    const empty: ServiceEndpoint = { type: PATH_HANDLER, path: '', serviceEndpoint: 'https://empty.example/' };
    const relative: ServiceEndpoint = { type: PATH_HANDLER, path: 'images', serviceEndpoint: 'https://rel.example/' };
    const missing: ServiceEndpoint = { type: PATH_HANDLER, serviceEndpoint: 'https://none.example/' };
    expect(selectPathHandler({ service: [empty, relative, missing] }, '/images/logo.png')).toBeUndefined();
  });

  test('on a tie the earlier service wins', () => {
    const other: ServiceEndpoint = { type: PATH_HANDLER, path: '/', serviceEndpoint: 'https://other.example/' };
    expect(url({ service: [storage, other] }, '/a')).toBe('https://provider.example/storage/a');
  });

  test('accepts a single service object and a bare string type', () => {
    const single: ServiceEndpoint = { type: 'PathHandler', path: '/x', serviceEndpoint: 'https://x.example' };
    const selection = selectPathHandler({ service: single }, '/x/y');
    expect(selection).toEqual({ service: single, remainder: '/y' });
  });

  test('pathHandlerUrl joins the endpoint and the remainder with exactly one slash', () => {
    const root = (serviceEndpoint: string, path: string) =>
      url({ service: [{ type: PATH_HANDLER, path: '/', serviceEndpoint }] }, path);
    expect(root('https://cdn.example', '/governance/issuers.json')).toBe('https://cdn.example/governance/issuers.json');
    expect(root('https://cdn.example/', '/governance/issuers.json')).toBe(
      'https://cdn.example/governance/issuers.json'
    );
    expect(root('https://cdn.example/', '/')).toBe('https://cdn.example/');
    expect(url({ service: [images] }, '/images')).toBe('https://cdn.example/img');
    const slashed: ServiceEndpoint = {
      type: PATH_HANDLER,
      path: '/images',
      serviceEndpoint: 'https://cdn.example/img/',
    };
    expect(url({ service: [slashed] }, '/images/logo.png')).toBe('https://cdn.example/img/logo.png');
  });

  test('accepts the service entries of a resolution result without a cast', () => {
    const service: { id?: string; type: string | string[]; serviceEndpoint: string | string[] } = {
      type: PATH_HANDLER,
      serviceEndpoint: 'https://x.example/',
    };
    expect(selectPathHandler({ service }, '/a')).toBeUndefined();
  });

  test('pathHandlerUrl handles a PathHandler of any additional type, and rejects a non-string endpoint', () => {
    const custom: ServiceEndpoint = {
      id: '#c',
      type: ['PathHandler', 'PathService', 'Custom'],
      path: '/c',
      serviceEndpoint: 'https://c.example',
    };
    expect(pathHandlerUrl({ service: custom, remainder: '/x' })).toBe('https://c.example/x');
    const multi: ServiceEndpoint = { type: PATH_HANDLER, path: '/m', serviceEndpoint: ['https://a', 'https://b'] };
    expect(() => pathHandlerUrl({ service: multi, remainder: '' })).toThrow(/single string serviceEndpoint/);
  });

  test('pathHandlerUrl rejects an endpoint that is not an absolute URI', () => {
    for (const serviceEndpoint of ['not-a-url', '/files', 'cdn.example/files', '']) {
      const service: ServiceEndpoint = { id: '#r', type: PATH_HANDLER, path: '/', serviceEndpoint };
      expect(() => pathHandlerUrl({ service, remainder: '/logo.png' })).toThrow(/must be an absolute URI/);
    }
    const ipfs: ServiceEndpoint = { type: PATH_HANDLER, path: '/', serviceEndpoint: 'ipfs://bafy/' };
    expect(pathHandlerUrl({ service: ipfs, remainder: '/logo.png' })).toBe('ipfs://bafy/logo.png');
  });

  test('pathHandlerUrl drops one trailing slash from the endpoint and keeps the remainder verbatim', () => {
    const doubled: ServiceEndpoint = { type: PATH_HANDLER, path: '/', serviceEndpoint: 'https://cdn.example//' };
    expect(pathHandlerUrl({ service: doubled, remainder: '/a' })).toBe('https://cdn.example//a');
    const plain: ServiceEndpoint = { type: PATH_HANDLER, path: '/', serviceEndpoint: 'https://cdn.example/' };
    expect(pathHandlerUrl({ service: plain, remainder: '//a' })).toBe('https://cdn.example//a');
  });

  test('pathHandlerUrl rejects an endpoint carrying a query or fragment', () => {
    for (const serviceEndpoint of ['https://cdn.example/files?token=abc', 'https://cdn.example/files#x']) {
      const service: ServiceEndpoint = { id: '#q', type: PATH_HANDLER, path: '/', serviceEndpoint };
      expect(() => pathHandlerUrl({ service, remainder: '/logo.png' })).toThrow(/must not carry a query or fragment/);
      expect(() => pathHandlerUrl({ service, remainder: '' })).toThrow(/must not carry a query or fragment/);
    }
  });
});

describe('dereference', () => {
  let did: string;
  let log: DIDLog;
  let deactivatedLog: DIDLog;
  let fetch: ReturnType<typeof createRoutedFetchMock>;
  let verifier: Verifier;

  beforeAll(async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    verifier = createTestVerifier(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });
    const updated = await updateDID({
      log: created.log,
      updated: nextSecond(created.log),
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      services: [storage],
    });
    did = created.did;
    log = updated.log;
    deactivatedLog = (
      await deactivateDID({
        log,
        signer,
        verifier,
        updateKeys: [authKey.publicKeyMultibase!],
      })
    ).log;
    stubGlobalFetchUnused();
    fetch = createRoutedFetchMock({ 'did.jsonl': log.map((entry) => JSON.stringify(entry)).join('\n') });
  });

  afterEach(() => {
    fetch.mockClear();
  });

  test('maps a DID URL path through the PathHandler service of the current document', async () => {
    await expect(dereference(`${did}/images/logo.png`, { verifier, fetch })).resolves.toBe(
      'https://provider.example/storage/images/logo.png'
    );
    expect(fetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl', expect.anything());
  });

  test('a version selector in the DID URL picks the document to dereference against', async () => {
    const v1 = log[0].versionId;
    await expect(dereference(`${did}/images/logo.png?versionId=${v1}`, { verifier, fetch })).rejects.toThrow(
      /No PathHandler service .* matches the path \/images\/logo.png/
    );
    await expect(dereference(`${did}/images/logo.png?versionNumber=2`, { verifier, fetch })).resolves.toBe(
      'https://provider.example/storage/images/logo.png'
    );
  });

  test('a version selector in the DID URL replaces the version selectors among the options', async () => {
    const v1 = log[0].versionId;
    await expect(
      dereference(`${did}/images/logo.png?versionNumber=2`, { verifier, fetch, versionId: v1 })
    ).resolves.toBe('https://provider.example/storage/images/logo.png');
    await expect(
      dereference(`${did}/images/logo.png?versionId=${v1}`, { verifier, fetch, versionTime: new Date() })
    ).rejects.toThrow(/No PathHandler service/);
    await expect(
      dereference(`${did}/images/logo.png?versionNumber=2`, { verifier, fetch, verificationMethod: `${did}#key-1` })
    ).resolves.toBe('https://provider.example/storage/images/logo.png');
  });

  test('a version selector among the options is kept when the DID URL has none', async () => {
    await expect(
      dereference(`${did}/images/logo.png`, { verifier, fetch, versionId: log[0].versionId })
    ).rejects.toThrow(/No PathHandler service/);
  });

  test('refuses to dereference against a document the resolver flagged with an error', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const witnessVerifier = createTestVerifier(authKey);
    const witnessed = await createDID({
      address: 'example.com',
      signer,
      verifier: witnessVerifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      services: [storage],
      witness: { threshold: 1, witnesses: [{ id: `did:key:${authKey.publicKeyMultibase}` }] },
    });
    const v1 = witnessed.log[0].versionId;
    const witnessProofs = [
      {
        versionId: v1,
        proof: [await createWitnessProof(createWitnessSigner(authKey), v1, witnessVerificationMethod(authKey))],
      },
    ];
    const twoVersions = await updateDID({
      log: witnessed.log,
      updated: nextSecond(witnessed.log),
      signer,
      verifier: witnessVerifier,
      witnessProofs,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      services: [storage],
    });
    // Only version 1 is witnessed. Selecting it returns its document, which
    // would dereference cleanly, decorated with `invalidDid` for version 2.
    const partlyWitnessed = createRoutedFetchMock({
      'did.jsonl': twoVersions.log.map((entry) => JSON.stringify(entry)).join('\n'),
      'did-witness.json': JSON.stringify(witnessProofs),
    });
    const resolved = await resolveDID(witnessed.did, {
      verifier: witnessVerifier,
      fetch: partlyWitnessed,
      versionId: v1,
    });
    expect(resolved.didDocument).not.toBeNull();
    expect(resolved.didResolutionMetadata.error).toBe('invalidDid');
    await expect(
      dereference(`${witnessed.did}/images/logo.png?versionId=${v1}`, {
        verifier: witnessVerifier,
        fetch: partlyWitnessed,
      })
    ).rejects.toThrow(/Could not resolve .*invalidDid.*Witness threshold not met/);
  });

  test('carries the fragment over to the result, and drops an empty one', async () => {
    await expect(dereference(`${did}/whois.vp#vp`, { verifier, fetch })).resolves.toBe(
      'https://provider.example/storage/whois.vp#vp'
    );
    await expect(dereference(`${did}/whois.vp#`, { verifier, fetch })).resolves.toBe(
      'https://provider.example/storage/whois.vp'
    );
  });

  test('refuses to dereference against a deactivated DID', async () => {
    const deactivated = createRoutedFetchMock({
      'did.jsonl': deactivatedLog.map((entry) => JSON.stringify(entry)).join('\n'),
    });
    await expect(dereference(`${did}/images/logo.png`, { verifier, fetch: deactivated })).rejects.toThrow(
      /is deactivated/
    );
    await expect(
      dereference(`${did}/images/logo.png?versionNumber=2`, { verifier, fetch: deactivated })
    ).rejects.toThrow(/is deactivated/);
  });

  test('rejects a DID URL without a path', async () => {
    await expect(dereference(did, { verifier, fetch })).rejects.toThrow(/has no path/);
    expect(fetch).not.toHaveBeenCalled();
  });

  test('surfaces a resolution failure', async () => {
    const missing = createRoutedFetchMock({});
    await expect(dereference(`${did}/a`, { verifier, fetch: missing })).rejects.toThrow(/Could not resolve .*notFound/);
    await expect(dereference(`${did}/a?versionId=1-x&versionNumber=2`, { verifier, fetch })).rejects.toThrow(
      /Could not resolve .*invalidOptions/
    );
  });
});
