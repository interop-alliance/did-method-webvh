import { describe, expect, test } from 'vitest';
import { normalizeCreateDidAddress } from '../src/utils/did-identifier.js';
import { getFileUrl } from '../src/utils.js';
import { createAndResolve, expectRoundTrip } from './utils.js';

// Regression coverage: every DID that createDID accepts must be a did:webvh
// identifier that resolveDIDFromLog accepts, and its DID-to-HTTPS
// transformation must follow did:webvh v1.0.
// Unicode test data is written with \u escapes to keep the source ASCII-only.

describe('createDID to resolveDIDFromLog round trip', () => {
  describe('additional {SCID} placeholders (spec: "inserting additional placeholder {SCID} strings")', () => {
    test('in a domain label', async () => {
      const result = await createAndResolve('{SCID}.example.com');
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:${scid}.example.com`);
      expect(getFileUrl(result.created.did)).toBe(
        `https://${result.created.log[0].parameters.scid!.toLowerCase()}.example.com/.well-known/did.jsonl`
      );
    });

    test('in a path segment', async () => {
      const result = await createAndResolve('example.com', ['users', '{SCID}']);
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:example.com:users:${scid}`);
      expect(getFileUrl(result.created.did)).toBe(
        `https://example.com/users/${result.created.log[0].parameters.scid}/did.jsonl`
      );
    });

    test('in domain, port-qualified domain and path together', async () => {
      const result = await createAndResolve('{SCID}.example.com:8443', ['{SCID}']);
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:${scid}.example.com%3A8443:${scid}`);
    });

    test('as part of a path segment', async () => {
      const result = await createAndResolve('example.com', ['tenant-{SCID}']);
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:example.com:tenant-${scid}`);
    });

    test('in the domain and path of a did:webvh template address', async () => {
      const result = await createAndResolve('did:webvh:{SCID}:{SCID}.example.com:{SCID}:x');
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:${scid}.example.com:${scid}:x`);
    });

    test('in the host and path of a URL address', async () => {
      const result = await createAndResolve('https://{SCID}.example.com/tenant-{SCID}/x');
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:${scid}.example.com:tenant-${scid}:x`);
    });

    test('an encoded placeholder in a URL path is literal text, as in the host', () => {
      const { controller } = normalizeCreateDidAddress({
        address: 'https://example.com/%7BSCID%7D',
        scid: '{SCID}',
        context: 'test',
      });
      expect(controller).toBe('did:webvh:{SCID}:example.com:%7BSCID%7D');
    });
  });

  describe('still rejected', () => {
    test.each([
      ['127.0.0.1', undefined],
      ['example.com', ['..']],
      ['example.com%2525', undefined],
      ['example', undefined],
      ['exa_mple.com', undefined],
      ['-example.com', undefined],
      [`${'a'.repeat(64)}.com`, undefined],
      [`${'a.'.repeat(127)}com`, undefined],
    ])('%s %j', async (address, paths) => {
      await expect(createAndResolve(address, paths as string[] | undefined)).rejects.toThrow();
    });
  });

  describe('localhost stays allowed for local testing', () => {
    test.each([
      ['localhost', 'localhost', 'http://localhost/.well-known/did.jsonl'],
      ['LOCALHOST', 'localhost', 'http://localhost/.well-known/did.jsonl'],
      ['localhost:8080', 'localhost%3A8080', 'http://localhost:8080/.well-known/did.jsonl'],
      ['http://localhost:8080', 'localhost%3A8080', 'http://localhost:8080/.well-known/did.jsonl'],
      ['did:webvh:{SCID}:localhost%3A8080', 'localhost%3A8080', 'http://localhost:8080/.well-known/did.jsonl'],
    ])('%s', async (address, location, fileUrl) => {
      const result = await createAndResolve(address);
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:${location}`);
      expect(getFileUrl(result.created.did)).toBe(fileUrl);
    });
  });

  describe('canonicalization is consistent across domains and paths', () => {
    test('an encoded %7BSCID%7D in the domain is literal text, not a placeholder', async () => {
      await expect(createAndResolve('%7BSCID%7D.example.com')).rejects.toThrow('valid fully qualified domain');
    });

    test('an encoded %7BSCID%7D in a path is literal text, not a placeholder', async () => {
      const result = await createAndResolve('example.com', ['%7BSCID%7D']);
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:example.com:%7BSCID%7D`);
    });

    test('domains are NFC-normalized so composition variants yield one DID', async () => {
      const decomposed = await createAndResolve('cafe\u0301.example.com');
      const composed = await createAndResolve('caf\u00e9.example.com');
      expectRoundTrip(decomposed, (scid) => `did:webvh:${scid}:xn--caf-dma.example.com`);
      expectRoundTrip(composed, (scid) => `did:webvh:${scid}:xn--caf-dma.example.com`);
    });

    test('path segments are left byte-exact', async () => {
      const result = await createAndResolve('example.com', ['cafe\u0301']);
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:example.com:cafe%CC%81`);
    });
  });

  describe('every address form yields one canonical DID (spec: DID-to-HTTPS steps 3-4)', () => {
    const canonical = (scid: string) => `did:webvh:${scid}:xn--fsq.example.com%3A8443:%E7%94%A8`;

    test.each([
      ['bare domain', '\u4f8b.example.com:8443', ['\u7528']],
      ['bare domain, lowercase hex and %3a', '%e4%be%8b.example.com%3a8443', ['%e7%94%a8']],
      ['HTTPS URL', 'https://\u4f8b.example.com:8443/\u7528', undefined],
      ['HTTPS URL, lowercase hex', 'https://%e4%be%8b.example.com:8443/%e7%94%a8', undefined],
      ['did:webvh, canonical', 'did:webvh:{SCID}:%E4%BE%8B.example.com%3A8443:%E7%94%A8', undefined],
      ['did:webvh, lowercase hex and %3a', 'did:webvh:{SCID}:%e4%be%8b.example.com%3a8443:%e7%94%a8', undefined],
      ['did:webvh, address path plus caller path', 'did:webvh:{SCID}:%e4%be%8b.example.com%3a8443', ['%e7%94%a8']],
    ])('%s', async (_name, address, paths) => {
      expectRoundTrip(await createAndResolve(address, paths), canonical);
    });

    test.each([
      ['bare domain', 'cafe\u0301.example.com'],
      ['HTTPS URL', 'https://cafe\u0301.example.com'],
      ['did:webvh', 'did:webvh:{SCID}:cafe%CC%81.example.com'],
    ])('NFD domain is NFC-normalized: %s', async (_name, address) => {
      expectRoundTrip(await createAndResolve(address), (scid) => `did:webvh:${scid}:xn--caf-dma.example.com`);
    });

    test('NFD path in a did:webvh address stays byte-exact', async () => {
      const result = await createAndResolve('did:webvh:{SCID}:example.com:cafe%cc%81');
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:example.com:cafe%CC%81`);
    });

    test('an ASCII domain is lowercased', async () => {
      expectRoundTrip(await createAndResolve('Example.COM'), (scid) => `did:webvh:${scid}:example.com`);
    });

    test.each([
      ['bare domain', 'Example.COM', ['Users']],
      ['HTTPS URL', 'https://Example.COM/Users', undefined],
      ['did:webvh', 'did:webvh:{SCID}:Example.COM:Users', undefined],
    ])('domain is lowercased, path case is preserved: %s', async (_name, address, paths) => {
      expectRoundTrip(await createAndResolve(address, paths), (scid) => `did:webvh:${scid}:example.com:Users`);
    });

    test.each([
      ['bare domain', 'B\u00dcCHER.example.com'],
      ['HTTPS URL', 'https://B\u00dcCHER.example.com'],
      ['did:webvh', 'did:webvh:{SCID}:B%C3%9CCHER.example.com'],
    ])('non-ASCII domain text is lowercased: %s', async (_name, address) => {
      expectRoundTrip(await createAndResolve(address), (scid) => `did:webvh:${scid}:xn--bcher-kva.example.com`);
    });

    test.each([
      ['bare domain', 'Tenant-{SCID}.Example.com'],
      ['did:webvh', 'did:webvh:{SCID}:Tenant-{SCID}.Example.com'],
    ])('a {SCID} placeholder in the domain is not case-folded: %s', async (_name, address) => {
      const result = await createAndResolve(address);
      expectRoundTrip(result, (scid) => `did:webvh:${scid}:tenant-${scid}.example.com`);
      expect(getFileUrl(result.created.did)).toBe(
        `https://tenant-${result.created.log[0].parameters.scid!.toLowerCase()}.example.com/.well-known/did.jsonl`
      );
    });
  });

  describe('ill-formed Unicode is rejected rather than replaced with U+FFFD', () => {
    test.each([
      ['unpaired high surrogate in a domain', 'a\uD800.example.com', undefined, 'Address input'],
      [
        'unpaired low surrogate in an HTTPS path (URL would encode it as %EF%BF%BD)',
        'https://example.com/a\uDC00',
        undefined,
        'Address input',
      ],
      ['unpaired high surrogate in a path segment', 'example.com', ['a\uD800'], 'createDID path segments'],
    ])('%s', async (_name, address, paths, context) => {
      await expect(createAndResolve(address, paths)).rejects.toThrow(
        `${context} contains ill-formed Unicode (unpaired surrogate)`
      );
    });
  });
});
