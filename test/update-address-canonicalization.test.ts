import { describe, expect, test } from 'vitest';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { getBaseUrl, normalizeUpdateDidAddress, parseDidWebvhIdentifier } from '../src/utils.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createUncanonicalizedDID,
  generateTestVerificationMethod,
  MOCK_SCID,
  TestCryptoImplementation,
} from './utils.js';

const createPortable = () => createUncanonicalizedDID({ did: 'did:webvh:{SCID}:example.com', portable: true });

describe('updateDID canonicalizes a new location', () => {
  test('a did:webvh address with lowercase hex is canonicalized on move', async () => {
    const { scid, update } = await createPortable();
    const updated = await update(`did:webvh:${scid}:%e4%be%8b.example.org%3a8443:%e7%94%a8`);
    expect(updated.did).toBe(`did:webvh:${scid}:xn--fsq.example.org%3A8443:%E7%94%A8`);
  });

  test('an uppercase host is lowercased on move', async () => {
    const { scid, update } = await createPortable();
    const updated = await update('Example.ORG');
    expect(updated.did).toBe(`did:webvh:${scid}:example.org`);
  });

  test('re-supplying the current location in another form is not a move', async () => {
    const { scid, update } = await createPortable();
    for (const address of ['EXAMPLE.com', 'https://Example.com', `did:webvh:${scid}:Example.com`]) {
      expect((await update(address)).did).toBe(`did:webvh:${scid}:example.com`);
    }
  });

  test('the actual SCID embedded in a domain keeps its case while the rest is lowercased', async () => {
    const { scid, update } = await createPortable();
    const updated = await update(`Tenant-${scid}.Example.org`);
    expect(updated.did).toBe(`did:webvh:${scid}:tenant-${scid}.example.org`);
  });

  test('previous path segments are re-canonicalized when carried over', () => {
    const result = normalizeUpdateDidAddress({
      address: 'example.org',
      scid: MOCK_SCID,
      priorPaths: ['%e7%94%a8', 'Users'],
      context: 'updateDID path segments',
    });
    expect(result.controller).toBe(`did:webvh:${MOCK_SCID}:example.org:%E7%94%A8:Users`);
  });
});

describe('updateDID rejects the {SCID} placeholder (spec: Create step 1)', () => {
  test.each([
    ['{SCID}.example.org', undefined],
    ['example.org', ['{SCID}']],
    ['example.org', ['tenant-{SCID}']],
  ])('%s %j', async (address, paths) => {
    const { update } = await createPortable();
    await expect(update(address, paths as string[] | undefined)).rejects.toThrow(
      'must not contain the {SCID} placeholder once the SCID has been generated'
    );
  });

  test('but accepts the actual SCID in domain and path', async () => {
    const { scid, update } = await createPortable();
    const updated = await update(`${scid}.example.org`, [scid]);
    expect(updated.did).toBe(`did:webvh:${scid}:${scid}.example.org:${scid}`);
  });

  test('a DID whose domain carries the SCID is not moved by re-supplying it', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const created = await createDID({
      address: '{SCID}.example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });
    const updated = await updateDID({
      log: created.log,
      address: created.did,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier,
    });
    expect(updated.did).toBe(created.did);
  });
});

describe('updateDID rejects a did:webvh address with another SCID', () => {
  test.each([
    ['a valid-shaped SCID', () => '1'.repeat(46)],
    ['a malformed SCID', () => 'not-a-scid'],
  ])('%s', async (_name, otherScid) => {
    const { scid, update } = await createPortable();
    await expect(update(`did:webvh:${otherScid()}:example.org`)).rejects.toThrow(
      /must carry the SCID of the DID being updated|must include a valid SCID/
    );
    expect(() =>
      normalizeUpdateDidAddress({
        address: `did:webvh:${otherScid()}:example.org`,
        scid,
        priorPaths: [],
        context: 'test',
      })
    ).toThrow();
  });
});

describe('updateDID with a non-canonical DID', () => {
  const uncanonicalizedDid = 'did:webvh:{SCID}:EXAMPLE.com:%e7%94%a8';

  test('the fixture really is non-canonical and still resolves', async () => {
    const { created, verifier } = await createUncanonicalizedDID({ did: uncanonicalizedDid });
    expect(created.did).toMatch(/:EXAMPLE\.com:%e7%94%a8$/);
    const resolved = await resolveDIDFromLog(created.log, { verifier });
    expect(resolved.doc?.id).toBe(created.did);
  });

  test.each([
    ['the non-canonical DID itself', (scid: string) => `did:webvh:${scid}:EXAMPLE.com:%e7%94%a8`, undefined],
    ['the canonical DID', (scid: string) => `did:webvh:${scid}:example.com:%E7%94%A8`, undefined],
    ['an HTTPS URL', () => 'https://example.com/\u7528', undefined],
    ['a bare domain carrying over the previous path', () => 'EXAMPLE.com', undefined],
    ['a bare domain with a raw Unicode path', () => 'example.com', ['\u7528']],
  ])('re-supplying the same location as %s keeps the DID', async (_name, address, paths) => {
    const { created, scid, update } = await createUncanonicalizedDID({ did: uncanonicalizedDid });
    const updated = await update(address(scid), paths);
    expect(updated.did).toBe(created.did);
  });

  test('a genuine move is canonicalized, including carried-over path segments', async () => {
    const { scid, update } = await createUncanonicalizedDID({ did: uncanonicalizedDid, portable: true });
    const updated = await update('Example.org');
    expect(updated.did).toBe(`did:webvh:${scid}:example.org:%E7%94%A8`);
  });

  test('a previous DID the address parser rejects does not block a move', async () => {
    // A U-label whose A-label exceeds 63 characters: resolution's
    // runtime-independent checks accept the identifier, but canonicalizing
    // it as an address fails. That failure must not be reported as the
    // requested move's error.
    const longLabel = encodeURIComponent(
      Array.from({ length: 60 }, (_, i) => String.fromCharCode(0x7528 + i)).join('')
    );
    const { created, scid, update } = await createUncanonicalizedDID({
      did: `did:webvh:{SCID}:${longLabel}.example`,
      portable: true,
    });
    expect(() => parseDidWebvhIdentifier(created.did, 'DID')).not.toThrow();
    expect(() => getBaseUrl(created.did)).toThrow('Host must be a valid fully qualified domain');
    const updated = await update('example.org');
    expect(updated.did).toBe(`did:webvh:${scid}:example.org`);
  });

  test('a genuine move is still rejected when portability is disabled', async () => {
    const { update } = await createUncanonicalizedDID({ did: uncanonicalizedDid, portable: false });
    await expect(update('example.org')).rejects.toThrow('Cannot move DID: portability is disabled');
  });
});
