import { describe, expect, test } from 'vitest';
import { createDID } from '../src/method.js';
import {
  getBaseUrl,
  getFileUrl,
  normalizeCreateDidAddress,
  parseCanonicalAddress,
  parseDidWebvhIdentifier,
} from '../src/utils/did-identifier.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  MOCK_SCID,
  TestCryptoImplementation,
} from './utils.js';

describe('Paths feature', () => {
  test('creates DID without paths (default behavior)', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Should only contain domain, no additional path components
    const didParts = doc.id!.split(':');
    expect(didParts.length).toBe(4); // did:webvh:${MOCK_SCID}:domain
    expect(didParts[3]).toBe('example.com');
  });

  test('creates DID with single path component', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'example.com',
      paths: ['api'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Should contain domain + single path component
    const didParts = doc.id!.split(':');
    expect(didParts.length).toBe(5); // did:webvh:${MOCK_SCID}:domain:path
    expect(didParts[3]).toBe('example.com');
    expect(didParts[4]).toBe('api');
  });

  test('creates DID with multiple path components', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'example.com',
      paths: ['api', 'v1', 'users'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Should contain domain + multiple path components
    const didParts = doc.id!.split(':');
    expect(didParts.length).toBe(7); // did:webvh:${MOCK_SCID}:domain:path1:path2:path3
    expect(didParts[3]).toBe('example.com');
    expect(didParts[4]).toBe('api');
    expect(didParts[5]).toBe('v1');
    expect(didParts[6]).toBe('users');
  });

  test('creates DID with empty paths array (should behave like no paths)', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'example.com',
      paths: [],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Should only contain domain, no additional path components
    const didParts = doc.id!.split(':');
    expect(didParts.length).toBe(4); // did:webvh:${MOCK_SCID}:domain
    expect(didParts[3]).toBe('example.com');
  });

  test('creates DID with paths containing special characters', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'example.com',
      paths: ['path-with-dash', 'path_with_underscore', 'path.with.dots'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Should contain domain + path components with special characters
    const didParts = doc.id!.split(':');
    expect(didParts.length).toBe(7); // did:webvh:${MOCK_SCID}:domain:path1:path2:path3
    expect(didParts[3]).toBe('example.com');
    expect(didParts[4]).toBe('path-with-dash');
    expect(didParts[5]).toBe('path_with_underscore');
    expect(didParts[6]).toBe('path.with.dots');
  });

  test('creates DID with domain requiring encoding and paths', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'localhost:3000',
      paths: ['api', 'health'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Should contain encoded domain + path components
    const didParts = doc.id!.split(':');
    expect(didParts.length).toBe(6); // did:webvh:${MOCK_SCID}:domain:path1:path2
    expect(didParts[3]).toBe('localhost%3A3000'); // domain should be encoded
    expect(didParts[4]).toBe('api');
    expect(didParts[5]).toBe('health');
  });

  test('controller field matches DID with paths', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'example.com',
      paths: ['api', 'v2'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Controller should match the DID ID
    expect(doc.controller).toBe(doc.id!);
    expect(doc.controller).toContain('example.com:api:v2');
  });

  test('verification method IDs include paths', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const { doc } = await createDID({
      address: 'example.com',
      paths: ['secure', 'keys'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    // Verification method ID should include the paths in the DID
    expect(doc.verificationMethod![0]!.id).toContain('example.com:secure:keys');
    // Verify the ID starts with the correct DID prefix
    expect(doc.verificationMethod![0]!.id!.startsWith(`${doc.id!}#`)).toBe(true);
  });

  test('rejects dot-segment in explicit paths array', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });

    await expect(
      createDID({
        address: 'example.com',
        paths: ['api', '..', 'secrets'],
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier,
      })
    ).rejects.toThrow('createDID path segments must not contain dot-segments');
  });

  test('rejects encoded slash inside a single explicit path segment', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });

    await expect(
      createDID({
        address: 'example.com',
        paths: ['api', 'a%2Fb'],
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier,
      })
    ).rejects.toThrow('createDID path segments must not contain decoded slash within a single path segment');
  });
});

describe('DID-to-HTTPS URL derivation', () => {
  test.each([
    ['%E7%94%A8%E6%88%B7', '%E7%94%A8%E6%88%B7'],
    ['%e7%94%a8%e6%88%b7', '%E7%94%A8%E6%88%B7'],
    ['%41b%2dc', 'Ab-c'],
    ['a%7eb', 'a~b'],
    ['a%21b%2Ac%3Ad', 'a%21b%2Ac%3Ad'],
    ['a%20b', 'a%20b'],
  ])('re-encodes path segment %s with uppercase hex', (segment, encoded) => {
    const did = `did:webvh:${MOCK_SCID}:example.com:${segment}`;
    expect(getBaseUrl(did)).toBe(`https://example.com/${encoded}`);
    expect(getFileUrl(did)).toBe(`https://example.com/${encoded}/did.jsonl`);
  });

  test('rejects empty path segments', () => {
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com::path`)).toThrow(
      'did:webvh identifier must not contain empty path segments'
    );
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:path:`)).toThrow();
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:`)).toThrow();
  });
});

describe('Address path encoding', () => {
  test.each([
    [`did:webvh:${MOCK_SCID}:example.com%3a8080:custom`, MOCK_SCID],
    ['did:webvh:{SCID}:example.com%3a8080:custom', '{SCID}'],
  ])('canonicalizes lowercase port separators in DID and template addresses', (address, scid) => {
    const normalized = normalizeCreateDidAddress({ address, scid, context: 'test' });
    expect(normalized.controller).toBe(`did:webvh:${scid}:example.com%3A8080:custom`);
    expect(parseCanonicalAddress(address).didDomainComponent).toBe('example.com%3A8080');
    expect(parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com%3a8080:custom`, 'test').didDomainComponent).toBe(
      'example.com%3A8080'
    );
  });

  test.each([
    ['https://example.com/a:b', 'a%3Ab', 'a%3Ab'],
    ['https://example.com/a%3ab', 'a%3Ab', 'a%3Ab'],
    ['https://example.com/~user/a b', '%7Euser:a%20b', '~user/a%20b'],
  ])('encodes URL path segments without changing their boundaries in %s', (address, didPath, urlPath) => {
    const normalized = normalizeCreateDidAddress({ address, scid: MOCK_SCID, context: 'test' });
    expect(normalized.controller).toBe(`did:webvh:${MOCK_SCID}:example.com:${didPath}`);
    expect(getFileUrl(normalized.controller)).toBe(`https://example.com/${urlPath}/did.jsonl`);
  });

  test('encodes supplied path segments once and canonicalizes existing DID paths', () => {
    const normalized = normalizeCreateDidAddress({
      address: `did:webvh:${MOCK_SCID}:example.com:a%7eb`,
      scid: MOCK_SCID,
      paths: ['a:b', 'a%3ab', '~user', 'a b'],
      context: 'test',
    });
    expect(normalized.controller).toBe(`did:webvh:${MOCK_SCID}:example.com:a%7Eb:a%3Ab:a%3Ab:%7Euser:a%20b`);
    expect(getFileUrl(normalized.controller)).toBe('https://example.com/a~b/a%3Ab/a%3Ab/~user/a%20b/did.jsonl');
  });

  test('normalizes an encoded did:webvh template address to its A-label form', () => {
    const address = 'did:webvh:{SCID}:b%C3%BCcher.example.com';
    expect(normalizeCreateDidAddress({ address, scid: '{SCID}', context: 'test' }).controller).toBe(
      'did:webvh:{SCID}:xn--bcher-kva.example.com'
    );
  });

  test('canonicalizes a plain did:webvh template address', () => {
    const address = 'did:webvh:{SCID}:example.com';
    expect(normalizeCreateDidAddress({ address, scid: '{SCID}', context: 'test' }).controller).toBe(address);
  });

  test('keeps {SCID} placeholders in the domain and path of a template address', () => {
    const address = 'did:webvh:{SCID}:{SCID}.example.com:{SCID}:x';
    expect(normalizeCreateDidAddress({ address, scid: '{SCID}', context: 'test' }).controller).toBe(address);
  });

  test('rejects invalid supplied path segments', () => {
    expect(() =>
      normalizeCreateDidAddress({ address: 'example.com', scid: MOCK_SCID, paths: [''], context: 'test' })
    ).toThrow('test must not contain empty path segments');
  });

  test('a DID created from a URL with a colon in its path round-trips to the file URL', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did } = await createDID({
      address: 'https://example.com/a:b',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: new TestCryptoImplementation({ verificationMethod: authKey }),
    });
    expect(did).toMatch(/^did:webvh:[^:]+:example\.com:a%3Ab$/);
    expect(getFileUrl(did)).toBe('https://example.com/a%3Ab/did.jsonl');
  });
});

describe('Port and path-segment syntax in did:webvh identifiers', () => {
  test.each(['8080x', 'x8080', '080801', '0', '65536', '8080.0', '-1'])(
    'rejects the malformed encoded port %s',
    (port) => {
      expect(() => parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com%3A${port}`, 'DID')).toThrow(
        `Invalid port number: ${port}`
      );
      expect(() => parseCanonicalAddress(`example.com:${port}`)).toThrow(`Invalid port number: ${port}`);
    }
  );

  test('accepts a port with a leading zero (1*5DIGIT) and canonicalizes it', () => {
    expect(parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com%3A08080`, 'DID').didDomainComponent).toBe(
      'example.com%3A8080'
    );
  });

  test.each(['a@b', 'a b', 'a~b', 'a!b', 'a(b)', 'a*b', "a'b", 'a%2', 'a%zz'])(
    'rejects the non-idchar path segment %s in a did:webvh identifier',
    (segment) => {
      expect(() => parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com:${segment}`, 'DID')).toThrow(
        `DID contains characters that are not DID Core idchars in path segment '${segment}'`
      );
      expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:${segment}`)).toThrow();
      expect(() => parseCanonicalAddress(`did:webvh:${MOCK_SCID}:example.com:${segment}`)).toThrow();
    }
  );

  test('accepts idchar path segments, including percent-encoded ones and a placeholder', () => {
    expect(parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com:a-b_c.d:%7Euser`, 'DID').paths).toEqual([
      'a-b_c.d',
      '%7Euser',
    ]);
    expect(
      normalizeCreateDidAddress({
        address: 'did:webvh:{SCID}:example.com:tenant-{SCID}',
        scid: '{SCID}',
        context: 'test',
      }).controller
    ).toBe('did:webvh:{SCID}:example.com:tenant-{SCID}');
  });
});

describe('Percent-encoded ASCII in a did:webvh host', () => {
  test.each(['exa%41mple.com', 'example%2Ecom', 'ex%2Dample.com'])('rejects %s in a did:webvh identifier', (host) => {
    const did = `did:webvh:${MOCK_SCID}:${host}`;
    expect(() => parseDidWebvhIdentifier(did, 'DID')).toThrow(
      'DID must not percent-encode ASCII characters in the host'
    );
    expect(() => getBaseUrl(did)).toThrow();
    expect(() => parseCanonicalAddress(did)).toThrow('must not percent-encode ASCII characters in the host');
  });

  test('still accepts a percent-encoded U-label host', () => {
    expect(parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:b%C3%BCcher.example`, 'DID').didDomainComponent).toBe(
      'b%C3%BCcher.example'
    );
  });

  test('canonicalizes a percent-encoded ASCII bare-domain address', () => {
    expect(parseCanonicalAddress('ex%61mple.com').didDomainComponent).toBe('example.com');
  });
});
