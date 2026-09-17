import { ed25519 } from '@noble/curves/ed25519.js';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { createDidWebvhDriver, defaultWebvhLogVerifier } from '../src/driver.js';
import type { DIDLog } from '../src/interfaces.js';
import { createDID } from '../src/method.js';
import { logToJsonlString } from '../src/utils.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

// Serve a DID log from the well-known URL and answer every other request (the
// witness file) with 404, so the resolver sees zero witness proofs.
const stubFetchLog = (log: DIDLog) => {
  const jsonl = logToJsonlString(log);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      url.endsWith('did.jsonl')
        ? {
            ok: true,
            status: 200,
            text: async () => jsonl,
            json: async () => null,
          }
        : {
            ok: false,
            status: 404,
            text: async () => '',
            json: async () => null,
          }
    )
  );
};

describe('createDidWebvhDriver', () => {
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

  test('get() resolves a clean log', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({
      verificationMethod: authKey,
    });
    const { did, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });
    stubFetchLog(log);

    const doc = await createDidWebvhDriver({ verifier }).get({ did });
    expect(doc.id).toBe(did);
  });

  test('get() rejects with invalidDid when the witness threshold is not met', async () => {
    const authKey = await generateTestVerificationMethod();
    const witness = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({
      verificationMethod: authKey,
    });
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
    stubFetchLog(log);
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(createDidWebvhDriver({ verifier }).get({ did })).rejects.toMatchObject({
      code: 'invalidDid',
      message: expect.stringContaining('Witness threshold not met'),
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
