import { afterEach, describe, expect, test, vi } from 'vitest';
import { deactivateDID, resolveDID } from '../src/method.js';
import { getBaseUrl, getFileUrl, parseCanonicalAddress, parseDidWebvhIdentifier } from '../src/utils.js';
import { createAndResolve, createUncanonicalizedDID, expectRoundTrip, MOCK_SCID } from './utils.js';

// Unicode test data is written with \u escapes to keep the source ASCII-only.
const BUCHER = 'b\u00fccher.example'; // xn--bcher-kva.example
const CHINESE = '\u4f8b\u5b50.\u6d4b\u8bd5'; // xn--fsqu00a.xn--0zwm56d
const ARABIC = '\u0645\u062b\u0627\u0644.\u0625\u062e\u062a\u0628\u0627\u0631'; // xn--mgbh0fb.xn--kgbechtv

describe('Internationalized domain handling', () => {
  test.each([
    ['percent-encoded U-label', `did:webvh:${MOCK_SCID}:${encodeURIComponent(BUCHER)}`],
    ['A-label', `did:webvh:${MOCK_SCID}:xn--bcher-kva.example`],
  ])('derives the A-label URL from a %s DID', (_name, did) => {
    expect(getBaseUrl(did)).toBe('https://xn--bcher-kva.example');
    expect(getFileUrl(did)).toBe('https://xn--bcher-kva.example/.well-known/did.jsonl');
  });

  test.each([
    ['percent-encoded U-label', `did:webvh:${MOCK_SCID}:${encodeURIComponent(CHINESE)}%3A8080`],
    ['A-label', `did:webvh:${MOCK_SCID}:xn--fsqu00a.xn--0zwm56d%3A8080`],
  ])('decodes encoded port numbers in a %s DID', (_name, did) => {
    expect(getBaseUrl(did)).toBe('https://xn--fsqu00a.xn--0zwm56d:8080');
    expect(getFileUrl(did)).toBe('https://xn--fsqu00a.xn--0zwm56d:8080/.well-known/did.jsonl');
  });

  test.each([
    ['percent-encoded U-label', `did:webvh:${MOCK_SCID}:${encodeURIComponent(ARABIC)}`],
    ['A-label', `did:webvh:${MOCK_SCID}:xn--mgbh0fb.xn--kgbechtv`],
  ])('arabic domain example as a %s DID', (_name, did) => {
    expect(getBaseUrl(did)).toBe('https://xn--mgbh0fb.xn--kgbechtv');
  });

  test.each([
    ['a malformed ASCII label', `b%C3%BCcher.-bad-.example`],
    ['a single label', 'b%C3%BCcher'],
    ['an over-long name', `b%C3%BCcher.${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(63)}`],
  ])('rejects a percent-encoded U-label identifier with %s at parse time', (_name, host) => {
    const did = `did:webvh:${MOCK_SCID}:${host}`;
    expect(() => parseDidWebvhIdentifier(did, 'DID')).toThrow('DID must include a valid fully qualified domain');
    expect(() => getFileUrl(did)).toThrow('must include a valid fully qualified domain');
  });

  test('keeps a percent-encoded U-label identifier as written', () => {
    const did = `did:webvh:${MOCK_SCID}:${encodeURIComponent(BUCHER)}`;
    expect(parseDidWebvhIdentifier(did, 'DID').didDomainComponent).toBe('b%C3%BCcher.example');
  });

  test.each([
    ['domain', `did:webvh:${MOCK_SCID}:${BUCHER}`],
    ['domain with port', `did:webvh:${MOCK_SCID}:${CHINESE}%3A8080`],
    ['path segment', `did:webvh:${MOCK_SCID}:example.com:\u7528\u6237`],
  ])('rejects raw (unencoded) Unicode in a DID %s', (_name, did) => {
    expect(() => parseDidWebvhIdentifier(did, 'DID')).toThrow('DID must be a valid did:webvh identifier');
    expect(() => getBaseUrl(did)).toThrow('must be a valid did:webvh identifier');
  });

  test('rejects raw Unicode in a did:webvh address on create', async () => {
    await expect(createAndResolve(`did:webvh:{SCID}:${BUCHER}`)).rejects.toThrow(
      'non-ASCII characters must be percent-encoded'
    );
  });
});

describe('createDID with internationalized domains and Unicode paths', () => {
  // Spec example: did:webvh:{SCID}:jp<natto>.<rei>.jp:<user>
  //   to https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl
  const rawDomain = 'jp\u7d0d\u8c46.\u4f8b.jp';
  const rawPath = '\u7528\u6237';
  const encodedDomain = 'jp%E7%B4%8D%E8%B1%86.%E4%BE%8B.jp';
  const encodedPath = '%E7%94%A8%E6%88%B7';
  const expectedUrl = 'https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl';

  test('uppercase Unicode domain becomes a lowercase A-label', async () => {
    const result = await createAndResolve('B\u00dcCHER.example.com');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--bcher-kva.example.com`);
  });

  test('raw Unicode domain becomes an A-label while the path is percent-encoded', async () => {
    const result = await createAndResolve(rawDomain, [rawPath]);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
    expect(getFileUrl(result.created.did)).toBe(expectedUrl);
  });

  test('HTTPS address yields the same canonical domain', async () => {
    const result = await createAndResolve(`https://${rawDomain}/${rawPath}`);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
    expect(getFileUrl(result.created.did)).toBe(expectedUrl);
  });

  test('pre-encoded domain and path produce the identical DID', async () => {
    const result = await createAndResolve(encodedDomain, [encodedPath]);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
    expect(getFileUrl(result.created.did)).toBe(expectedUrl);
  });

  test('lowercase pre-encoding is canonicalized to uppercase hex', async () => {
    const result = await createAndResolve(encodedDomain.toLowerCase(), [encodedPath.toLowerCase()]);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
  });

  test.each([
    ['percent-encoded U-label', `did:webvh:{SCID}:${encodedDomain}:${encodedPath}`],
    ['A-label', `did:webvh:{SCID}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`],
  ])('a %s did:webvh template yields the A-label DID', async (_name, address) => {
    const result = await createAndResolve(address);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
  });

  test('NFD domain input is NFC-normalized before conversion', async () => {
    const result = await createAndResolve('bu\u0308cher.example.com');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--bcher-kva.example.com`);
  });

  test('IDN with a port', async () => {
    const result = await createAndResolve('\u4f8b\u3048.\u30c6\u30b9\u30c8:8443');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--r8jz45g.xn--zckzah%3A8443`);
    expect(getFileUrl(result.created.did)).toBe('https://xn--r8jz45g.xn--zckzah:8443/.well-known/did.jsonl');
  });

  test('HTTPS address keeps an IDN with an explicit port', async () => {
    const result = await createAndResolve('https://\u4f8b\u3048.\u30c6\u30b9\u30c8:8443');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--r8jz45g.xn--zckzah%3A8443`);
    expect(getFileUrl(result.created.did)).toBe('https://xn--r8jz45g.xn--zckzah:8443/.well-known/did.jsonl');
  });

  test('non-idchar ASCII in a path segment is percent-encoded', async () => {
    const result = await createAndResolve('example.com', ['a~b', 'c d', "!'()*"]);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:example.com:a%7Eb:c%20d:%21%27%28%29%2A`);
  });

  test('IDN combined with {SCID} placeholders', async () => {
    const result = await createAndResolve('{SCID}.\u4f8b.jp', [rawPath, '{SCID}']);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:${scid}.xn--fsq.jp:${encodedPath}:${scid}`);
  });

  test('rejects Unicode and {SCID} in the same domain label', () => {
    expect(() => parseCanonicalAddress('{SCID}\u4f8b.jp')).toThrow('Unicode and {SCID} cannot share a domain label');
  });

  test('rejects an unpaired surrogate', () => {
    expect(() => parseCanonicalAddress('\uD800.example.com')).toThrow(
      'Address input contains ill-formed Unicode (unpaired surrogate)'
    );
  });
});

describe('non-canonical percent-encoded U-label DIDs', () => {
  const uncanonicalizedDid = 'did:webvh:{SCID}:b%C3%BCcher.example.com';

  function servedLog(log: unknown[], fetched: string[]) {
    return async (url: string) => {
      fetched.push(url);
      return new Response(log.map((entry) => JSON.stringify(entry)).join('\n'), { status: 200 });
    };
  }

  test('resolution keeps the DID while fetching the A-label host', async () => {
    const { created, verifier } = await createUncanonicalizedDID({ did: uncanonicalizedDid });
    const fetched: string[] = [];
    const result = await resolveDID(created.did, { verifier, fetch: servedLog(created.log, fetched) });
    expect(fetched).toEqual(['https://xn--bcher-kva.example.com/.well-known/did.jsonl']);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(created.did);
  });

  test('updating with the same location keeps the non-canonical DID', async () => {
    const { created, update } = await createUncanonicalizedDID({ did: uncanonicalizedDid });
    expect((await update(created.did)).did).toBe(created.did);
    expect((await update('b\u00fccher.example.com')).did).toBe(created.did);
    expect((await update('xn--bcher-kva.example.com')).did).toBe(created.did);
  });

  test('deactivateDID keeps the non-canonical DID', async () => {
    const { created, signer, updateKeys, verifier } = await createUncanonicalizedDID({ did: uncanonicalizedDid });
    const deactivated = await deactivateDID({ log: created.log, signer, updateKeys, verifier });
    expect(deactivated.did).toBe(created.did);
    expect(deactivated.meta.deactivated).toBe(true);
  });
});

describe('runtimes whose URL does not support IDNA', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test('Unicode hosts are rejected with a clear error; ASCII hosts still work', async () => {
    vi.resetModules();
    const parser = await import('../src/utils/did-identifier.js');
    const RealURL = URL;
    vi.stubGlobal(
      'URL',
      class extends RealURL {
        override get hostname() {
          return super.hostname.replace(/^xn--/, '');
        }
      }
    );

    const idnaError = "This runtime's URL implementation does not support IDNA; use an A-label (xn--) domain instead";
    expect(() => parser.parseCanonicalAddress(BUCHER)).toThrow(idnaError);
    expect(() => parser.getBaseUrl(`did:webvh:${MOCK_SCID}:b%C3%BCcher.example`)).toThrow(idnaError);
    expect(parser.parseCanonicalAddress('xn--bcher-kva.example').didDomainComponent).toBe('xn--bcher-kva.example');
    expect(parser.getBaseUrl(`did:webvh:${MOCK_SCID}:xn--bcher-kva.example`)).toBe('https://xn--bcher-kva.example');
  });
});
