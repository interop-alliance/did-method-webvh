import { describe, expect, test } from 'vitest';
import { fetchLogFromIdentifier, getBaseUrl, parseDidWebvh, readLogFromString } from '../src/index.js';

const SCID = 'QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ';

describe('fetchLogFromIdentifier', () => {
  test('is exported from the package index and requests the log URL', async () => {
    const requested: string[] = [];
    const fetchFn = async (url: string | URL | Request) => {
      requested.push(String(url));
      return new Response(null, { status: 404 });
    };
    await expect(fetchLogFromIdentifier(`did:webvh:${SCID}:example.com`, fetchFn)).rejects.toMatchObject({
      code: 'notFound',
    });
    expect(requested).toEqual(['https://example.com/.well-known/did.jsonl']);
  });

  const body = (text: string) => async () => new Response(text, { status: 200 });

  test.each([
    ['an HTML body', '<html>', 'DID log line 1 is not valid JSON'],
    ['a JSON value that is not an object', '42', 'DID log line 1 is not a JSON object'],
    ['a blank line between entries', '{}\n\n{}', 'DID log line 2 is not valid JSON'],
  ])('throws a plain error for %s', async (_case, text, message) => {
    const error = await fetchLogFromIdentifier(`did:webvh:${SCID}:example.com`, body(text)).catch((e) => e);
    expect(error.message).toBe(message);
    expect(error.code).toBeUndefined();
  });

  test('throws a plain error for an invalid identifier', async () => {
    const error = await fetchLogFromIdentifier('did:web:example.com', body('{}')).catch((e) => e);
    expect(error.message).toBe('did:webvh identifier must be a valid did:webvh identifier');
    expect(error.code).toBeUndefined();
  });
});

describe('readLogFromString', () => {
  test.each([
    ['null', 'null'],
    ['an array', '[]'],
    ['a string', '"entry"'],
  ])('rejects a line holding %s', (_case, line) => {
    expect(() => readLogFromString(`{}\n${line}`)).toThrow('DID log line 2 is not a JSON object');
  });
});

describe('parseDidWebvh', () => {
  test('decomposes a DID with port and path', () => {
    const parsed = parseDidWebvh(`did:webvh:${SCID}:example.com%3A8443:dids:caf%C3%A9`);
    expect(parsed).toEqual({
      did: `did:webvh:${SCID}:example.com%3A8443:dids:caf%C3%A9`,
      scid: SCID,
      domainComponent: 'example.com%3A8443',
      host: 'example.com',
      port: 8443,
      pathSegments: ['dids', 'caf\u00e9'],
    });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.pathSegments)).toBe(true);
  });

  test('omits port and returns empty path segments for a bare domain', () => {
    const parsed = parseDidWebvh(`did:webvh:${SCID}:example.com`);
    expect(parsed).not.toHaveProperty('port');
    expect(parsed.pathSegments).toEqual([]);
  });

  test('returns a percent-encoded U-label host decoded', () => {
    const parsed = parseDidWebvh(`did:webvh:${SCID}:b%C3%BCcher.example`);
    expect(parsed.host).toBe('b\u00fccher.example');
    expect(parsed.domainComponent).toBe('b%C3%BCcher.example');
  });

  // This fork allows `localhost` for local development and testing.
  test('accepts localhost with a port', () => {
    const parsed = parseDidWebvh(`did:webvh:${SCID}:localhost%3A3000`);
    expect(parsed.host).toBe('localhost');
    expect(parsed.port).toBe(3000);
  });

  test('returns the domain component as written in the DID', () => {
    const lowercaseSeparator = parseDidWebvh(`did:webvh:${SCID}:example.com%3a8443`);
    expect(lowercaseSeparator.domainComponent).toBe('example.com%3a8443');
    expect(lowercaseSeparator.port).toBe(8443);

    const leadingZeros = parseDidWebvh(`did:webvh:${SCID}:example.com%3A00080`);
    expect(leadingZeros.domainComponent).toBe('example.com%3A00080');
    expect(leadingZeros.port).toBe(80);
  });

  test('returns the host in the letter case of the DID', () => {
    const did = `did:webvh:${SCID}:Example.COM`;
    const parsed = parseDidWebvh(did);
    expect(parsed.host).toBe('Example.COM');
    expect(parsed.domainComponent).toBe('Example.COM');
    expect(getBaseUrl(did)).toBe('https://example.com');
  });

  test.each([
    ['another method', `did:web:example.com`, 'did:webvh identifier must be a valid did:webvh identifier'],
    ['a malformed SCID', 'did:webvh:abc:example.com', 'did:webvh identifier must include a valid SCID'],
    ['no domain', `did:webvh:${SCID}`, 'did:webvh identifier must be a valid did:webvh identifier'],
    ['a single-label host', `did:webvh:${SCID}:example`, 'Host must be a valid fully qualified domain'],
    ['an IP address host', `did:webvh:${SCID}:127.0.0.1`, 'IP addresses are not allowed as hosts'],
    ['an IP-shaped host with a U-label', `did:webvh:${SCID}:b%C3%BCcher.127`, 'IP addresses are not allowed as hosts'],
    ['an out-of-range port', `did:webvh:${SCID}:example.com%3A70000`, 'Invalid port number: 70000'],
    ['a dot-segment', `did:webvh:${SCID}:example.com:..`, 'did:webvh identifier must not contain dot-segments'],
    [
      'a fragment',
      `did:webvh:${SCID}:example.com#key-1`,
      'Address input must not include query or fragment components',
    ],
    [
      'a query',
      `did:webvh:${SCID}:example.com?versionId=1`,
      'Address input must not include query or fragment components',
    ],
    ['a DID URL path', `did:webvh:${SCID}:example.com/whois`, 'did:webvh identifier must not include a DID URL path'],
    ['a {SCID} template', 'did:webvh:{SCID}:example.com', 'did:webvh identifier must include a valid SCID'],
    ['a non-string', 42 as unknown as string, 'did:webvh identifier must be a string'],
  ])('rejects %s', (_case, did, message) => {
    expect(() => parseDidWebvh(did)).toThrow(new Error(message));
  });
});
