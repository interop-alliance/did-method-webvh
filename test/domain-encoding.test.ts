import { describe, expect, test } from 'vitest';
import { createDID } from '../src/method.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

type InputKind = 'domain' | 'address';

async function createFromInput(kind: InputKind, value: string) {
  const authKey = await generateTestVerificationMethod();
  const verifier = new TestCryptoImplementation({ verificationMethod: authKey });

  const baseOptions = {
    signer: createTestSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
    verifier,
  };

  if (kind === 'domain') {
    return createDID({
      ...baseOptions,
      address: value,
    });
  }

  return createDID({
    ...baseOptions,
    address: value,
  });
}

describe('Strict address input validation and parsing', () => {
  test('accepts host-only domain input', async () => {
    const { doc } = await createFromInput('domain', 'example.com');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com$/);
  });

  test('Accepts host:port domain input with canonical %3A encoding', async () => {
    const { doc } = await createFromInput('domain', 'example.com:443');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A443$/);
  });

  test('Accepts pre-encoded host%3Aport without double encoding', async () => {
    const { doc } = await createFromInput('domain', 'localhost%3A8000');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000$/);
  });

  test('Accepts pre-encoded host%3aport with lowercase separator and canonicalizes output', async () => {
    const { doc } = await createFromInput('domain', 'localhost%3a8000');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000$/);
  });

  test('Accepts https URL address input', async () => {
    const { doc } = await createFromInput('address', 'https://example.com/');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com$/);
  });

  test('Accepts URL with explicit port', async () => {
    const { doc } = await createFromInput('address', 'https://example.com:8080/');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A8080$/);
  });

  test('Accepts URL with custom path and converts to colon-delimited DID path', async () => {
    const { doc } = await createFromInput('address', 'https://example.com/custom/path');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com:custom:path$/);
  });

  test('Accepts localhost HTTP URL with path and port', async () => {
    const { doc } = await createFromInput('address', 'http://localhost:8000/test');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000:test$/);
  });

  test('Accepts localhost HTTPS URL with path and port', async () => {
    const { doc } = await createFromInput('address', 'https://localhost:8000/test');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000:test$/);
  });

  test('Accepts canonical did:webvh input with port and path', async () => {
    const { doc } = await createFromInput('address', 'did:webvh:{SCID}:example.com%3A8080:custom:path');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A8080:custom:path$/);
  });

  test('Canonicalizes a lowercase port separator in a DID template', async () => {
    const { doc } = await createFromInput('address', 'did:webvh:{SCID}:example.com%3a8080:custom');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A8080:custom$/);
  });

  test('Keeps colons within URL path segments when creating a DID', async () => {
    const { did, doc } = await createFromInput('address', 'https://example.com/a:b');
    expect(did).toMatch(/^did:webvh:[^:]+:example\.com:a%3Ab$/);
    expect(doc.id).toBe(did);
  });

  test.each(['https://user:pass@example.com', 'https://example.com:1@other.org/', 'https://localhost:1@evil.com/'])(
    'Rejects URL input with userinfo: %s',
    async (address) => {
      await expect(createFromInput('address', address)).rejects.toThrow(
        'URL input must not include username or password'
      );
    }
  );

  test('Rejects unsupported URL scheme', async () => {
    expect(createFromInput('address', 'ftp://example.com')).rejects.toThrow();
  });

  test('Rejects HTTP URL for non-local host', async () => {
    expect(createFromInput('address', 'http://example.com')).rejects.toThrow();
  });

  test('Rejects out-of-range port', async () => {
    expect(createFromInput('domain', 'example.com:999999')).rejects.toThrow();
  });

  test('Rejects IPv4 host input', async () => {
    expect(createFromInput('domain', '192.168.1.10')).rejects.toThrow();
  });

  test('Rejects double-encoded separator', async () => {
    expect(createFromInput('domain', 'example.com%253A8080')).rejects.toThrow();
  });

  test('Rejects mangled host:port input', async () => {
    expect(createFromInput('domain', '%%%bad host%%%::notaport::')).rejects.toThrow();
  });

  test('Rejects mangled URL input', async () => {
    expect(createFromInput('address', 'https://%%%bad host%%%::notaport::/%%%')).rejects.toThrow();
  });

  test('Rejects encoded IPv4 host input', async () => {
    expect(createFromInput('domain', '127%2E0%2E0%2E1')).rejects.toThrow('IP addresses are not allowed as hosts');
  });

  test('Rejects lowercase encoded-port IP host input', async () => {
    expect(createFromInput('domain', '127.0.0.1%3a8080')).rejects.toThrow('IP addresses are not allowed as hosts');
  });

  test('Rejects did:webvh input containing fragment contamination', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com#frag')).rejects.toThrow(
      'Address input must not include query or fragment components'
    );
  });

  test('Rejects did:webvh input containing query contamination', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com?query=1')).rejects.toThrow(
      'Address input must not include query or fragment components'
    );
  });

  test('Rejects did:webvh input containing dot-segment path traversal', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:..:secrets')).rejects.toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
  });

  test('Rejects did:webvh input containing percent-encoded traversal segment', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:%2E%2E:secrets')).rejects.toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
  });

  test('Rejects did:webvh input containing decoded slash within one path segment', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:a%2Fb')).rejects.toThrow(
      'did:webvh identifier must not contain decoded slash within a single path segment'
    );
  });

  test('Rejects decoded backslash in path segment', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:test%5Csecret')).rejects.toThrow(
      'did:webvh identifier must not contain decoded backslash within a path segment'
    );
  });

  test.each([
    ['NUL', 'did:webvh:{SCID}:example.com:test%00secret', 'did:webvh identifier'],
    ['tab', 'did:webvh:{SCID}:example.com:a%09b', 'did:webvh identifier'],
    // WHATWG URL strips tab, CR, and LF before parsing; the raw text is checked.
    ['raw tab in a URL path', 'https://example.com/a\tb', 'URL pathname'],
    ['raw newline in a URL path', 'https://example.com/a\nb', 'URL pathname'],
  ])('Rejects decoded control character (%s) in path segment', async (_name, address, context) => {
    await expect(createFromInput('address', address)).rejects.toThrow(
      `${context} must not contain decoded control characters within a path segment`
    );
  });

  test('Rejects a raw tab in the paths option', async () => {
    const authKey = await generateTestVerificationMethod();
    await expect(
      createDID({
        address: 'example.com',
        paths: ['a\tb'],
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: new TestCryptoImplementation({ verificationMethod: authKey }),
      })
    ).rejects.toThrow('must not contain decoded control characters within a path segment');
  });

  test.each(['127.1', '0x7f.1', '01.1', '0177.0.0.1', '2130706433'])(
    'Rejects non-dotted-quad IPv4 literal host %s in every input form',
    async (host) => {
      await expect(createFromInput('domain', host)).rejects.toThrow('IP addresses are not allowed as hosts');
      await expect(createFromInput('address', `did:webvh:{SCID}:${host}`)).rejects.toThrow(
        'IP addresses are not allowed as hosts'
      );
      await expect(createFromInput('address', `https://${host}/`)).rejects.toThrow(
        'IP addresses are not allowed as hosts'
      );
    }
  );

  test('Rejects a host whose last label is numeric, as WHATWG URL reads it as IPv4', async () => {
    await expect(createFromInput('domain', 'example.123')).rejects.toThrow('IP addresses are not allowed as hosts');
    await expect(createFromInput('address', 'did:webvh:{SCID}:example.123')).rejects.toThrow(
      'IP addresses are not allowed as hosts'
    );
  });

  test('Accepts a host label that happens to be SCID-shaped', async () => {
    const label = '1'.repeat(46);
    const { did, doc } = await createFromInput('domain', `${label}.example.com`);
    expect(did).toMatch(new RegExp(`^did:webvh:[^:]+:${label}\\.example\\.com$`));
    expect(doc.alsoKnownAs).toBeUndefined();
  });

  test('Rejects leading whitespace in decoded path segment', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:%20test')).rejects.toThrow(
      'did:webvh identifier must not contain leading or trailing whitespace in decoded path segment'
    );
  });

  test('Rejects trailing whitespace in decoded path segment', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:test%20')).rejects.toThrow(
      'did:webvh identifier must not contain leading or trailing whitespace in decoded path segment'
    );
  });
});
