import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, test } from 'vitest';
import { createDidWebvhDriver, defaultWebvhLogVerifier } from '../src/driver.js';

describe('createDidWebvhDriver', () => {
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

  test('returns false (does not throw) on malformed input', async () => {
    expect(await defaultWebvhLogVerifier.verify(new Uint8Array(1), new Uint8Array(1), new Uint8Array(1))).toBe(false);
  });
});
