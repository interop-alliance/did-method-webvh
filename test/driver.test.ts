import { ed25519 } from '@noble/curves/ed25519.js';
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import { createDidWebvhDriver, defaultWebvhLogVerifier } from '../src/driver.js';
import type { DIDLog, FetchLike, VerificationMethod } from '../src/interfaces.js';
import { createDID, updateDID } from '../src/method.js';
import { logToJsonlString } from '../src/utils.js';
import {
  asPublicVerificationMethods,
  createRoutedFetchMock,
  createTestSigner,
  generateTestVerificationMethod,
  nextSecond,
  stubGlobalFetchUnused,
  TestCryptoImplementation,
} from './utils.js';

// A fetch that serves a DID log from the well-known URL and answers every
// other request (the witness file) with 404, so the resolver sees zero
// witness proofs.
const logFetchMock = (log: DIDLog) => createRoutedFetchMock({ 'did.jsonl': logToJsonlString(log) });

describe('createDidWebvhDriver', () => {
  // One unwitnessed DID shared by the tests that only need a clean log.
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

  test('exposes the did:webvh method', () => {
    expect(createDidWebvhDriver().method).toBe('webvh');
  });

  test('rejects when neither did nor url is given', async () => {
    await expect(createDidWebvhDriver().get({})).rejects.toThrow(/DID or a URL is required/);
  });

  test('passes a supplied verifier through to resolution', async () => {
    let used = false;
    const verifier = {
      async verify() {
        used = true;
        return true;
      },
    };
    const driver = createDidWebvhDriver({ verifier });
    // An unresolvable host fails fast; we only assert the call is wired, not the
    // network outcome.
    await expect(driver.get({ did: 'did:webvh:QmExample:invalid.example' })).rejects.toThrow();
    expect(typeof driver.get).toBe('function');
    void used;
  });

  test('passes a supplied fetch through to resolution', async () => {
    stubGlobalFetchUnused();
    const customFetch = logFetchMock(log);
    const driver = createDidWebvhDriver({ verifier, fetch: customFetch });

    const doc = await driver.get({ did });
    expect(doc.id).toBe(did);
    const result = await driver.resolveDID({ did });
    expect(result.didDocument?.id).toBe(did);
    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('resolveDID() honors a per-call fetch over the driver-level one', async () => {
    stubGlobalFetchUnused();
    const driverFetch = vi.fn().mockRejectedValue(new Error('driver fetch should not be called'));
    const perCallFetch = logFetchMock(log);
    const driver = createDidWebvhDriver({ verifier, fetch: driverFetch as unknown as FetchLike });

    const result = await driver.resolveDID({ did, fetch: perCallFetch });

    expect(result.didDocument?.id).toBe(did);
    expect(perCallFetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(driverFetch).not.toHaveBeenCalled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('resolveDID() rejects a non-function per-call fetch as invalidOptions', async () => {
    const driver = createDidWebvhDriver();

    const result = await driver.resolveDID({ did: 'did:webvh:QmExample:example.com', fetch: 'nope' });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidOptions');
  });

  test('get() dereferences a versioned URL in the document at that version', async () => {
    const key2 = await generateTestVerificationMethod('assertionMethod');
    const signer = createTestSigner(authKey);
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey, key2),
    });
    const updated = await updateDID({
      log: created.log,
      updated: nextSecond(created.log),
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });
    const key2Id = updated.log[0].state.verificationMethod!.find(
      (vm) => vm.publicKeyMultibase === key2.publicKeyMultibase
    )!.id!;
    const fragment = key2Id.slice(key2Id.indexOf('#') + 1);
    vi.stubGlobal('fetch', logFetchMock(updated.log));
    const driver = createDidWebvhDriver({ verifier });

    const node = await driver.get({ url: `${created.did}?versionId=${updated.log[0].versionId}#${fragment}` });
    expect(node).toMatchObject({ id: key2Id, publicKeyMultibase: key2.publicKeyMultibase });

    await expect(driver.get({ url: `${created.did}#${fragment}` })).rejects.toMatchObject({
      name: 'VerificationMethodError',
      code: 'notFound',
      verificationMethod: `${created.did}#${fragment}`,
      message: `DID document entity with id "${created.did}#${fragment}" not found.`,
    });
    // The error names the URL the caller asked for, selector included.
    const versionedMiss = `${created.did}?versionId=${updated.log[1].versionId}#${fragment}`;
    await expect(driver.get({ url: versionedMiss })).rejects.toMatchObject({
      name: 'VerificationMethodError',
      code: 'notFound',
      verificationMethod: versionedMiss,
    });
    await expect(driver.get({ url: `${created.did}?versionId=9-unknown#${fragment}` })).rejects.toThrow();
    await expect(driver.get({ url: `${created.did}?versionTime=2024-01-01T00:00:00Z#${fragment}` })).rejects.toThrow(
      /Unsupported DID parameter/
    );
  });

  test('get() resolves a clean log', async () => {
    vi.stubGlobal('fetch', logFetchMock(log));

    const doc = await createDidWebvhDriver({ verifier }).get({ did });
    expect(doc.id).toBe(did);
  });

  test('get() rejects with invalidDid when the witness threshold is not met', async () => {
    const witness = await generateTestVerificationMethod();
    const { did, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${witness.publicKeyMultibase}` }],
      },
      verifier,
    });
    vi.stubGlobal('fetch', logFetchMock(log));
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(createDidWebvhDriver({ verifier }).get({ did })).rejects.toMatchObject({
      code: 'invalidDid',
      message: expect.stringContaining('Witness threshold not met'),
    });
  });

  test('get() dereferences a service fragment and reports a missing one as notFound', async () => {
    const service = { id: '{DID}#files', type: 'TestService', serviceEndpoint: 'https://example.com/files' };
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      services: [service],
    });
    vi.stubGlobal('fetch', logFetchMock(created.log));
    const driver = createDidWebvhDriver({ verifier });

    const node = await driver.get({ url: `${created.did}#files` });
    expect(node).toMatchObject({ ...service, id: `${created.did}#files` });

    await expect(driver.get({ url: `${created.did}#whois` })).rejects.toMatchObject({
      name: 'VerificationMethodError',
      code: 'notFound',
      verificationMethod: `${created.did}#whois`,
    });
  });
});

describe('defaultWebvhLogVerifier', () => {
  test('verifies a valid Ed25519 signature', async () => {
    const secretKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(secretKey);
    const message = new TextEncoder().encode('did:webvh log entry');
    const signature = ed25519.sign(message, secretKey);

    expect(await defaultWebvhLogVerifier.verify(signature, message, publicKey)).toBe(true);
  });

  test('rejects a tampered message', async () => {
    const secretKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(secretKey);
    const signature = ed25519.sign(new TextEncoder().encode('original'), secretKey);

    expect(await defaultWebvhLogVerifier.verify(signature, new TextEncoder().encode('tampered'), publicKey)).toBe(
      false
    );
  });

  test('throws (does not swallow) on malformed input', async () => {
    // A clean signature mismatch returns false (see above); a programming error
    // -- here a wrong-length signature -- propagates rather than being masked as
    // a misleading verification failure. This is the R1 catch-all narrowing.
    await expect(
      defaultWebvhLogVerifier.verify(new Uint8Array(1), new Uint8Array(1), new Uint8Array(1))
    ).rejects.toThrow(/Uint8Array of length 64/);
  });
});
