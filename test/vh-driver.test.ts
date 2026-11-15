import { afterEach, describe, expect, test, vi } from 'vitest';
import type { DIDLog, WitnessProofFileEntry } from '../src/interfaces.js';
import { logToJsonlString } from '../src/utils.js';
import { updateDID } from '../src/vh.js';
import { createDidVhDriver } from '../src/vh-driver.js';
import { nextSecond, stubGlobalFetchUnused } from './utils.js';
import { createThreeEntryVh, createUrlFetch, createVhFixture, createWitnessedVh } from './vh-helpers.js';

/** A `loadLog` callback serving `log` for `did`, recording the DIDs it was asked for. */
const storedLog = (did: string, didLog: DIDLog, didWitness?: WitnessProofFileEntry[]) =>
  vi.fn(async (asked: { did: string }) => (asked.did === did ? { didLog, didWitness } : undefined));

/** A copy of `log` whose last entry carries a proof that does not verify. */
const withCorruptTail = (log: DIDLog): DIDLog => {
  const copy = structuredClone(log);
  const proof = copy[copy.length - 1].proof![0];
  const last = proof.proofValue.at(-1);
  proof.proofValue = `${proof.proofValue.slice(0, -1)}${last === '2' ? '3' : '2'}`;
  return copy;
};

describe('createDidVhDriver', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  test('exposes the did:vh method', () => {
    expect(createDidVhDriver().method).toBe('vh');
  });

  test('rejects when neither did nor url is given', async () => {
    await expect(createDidVhDriver().get({})).rejects.toThrow(/DID or a URL is required/);
  });

  test('get() resolves a DID from the log loadLog returns, with no network request', async () => {
    stubGlobalFetchUnused();
    const f = await createVhFixture();
    const loadLog = storedLog(f.did, f.log);
    const driver = createDidVhDriver({ loadLog, verifier: f.verifier });

    const doc = await driver.get({ did: f.did });
    expect(doc.id).toBe(f.did);
    expect(loadLog).toHaveBeenCalledWith({ did: f.did });
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('get() accepts the log as JSON Lines text', async () => {
    const f = await createVhFixture();
    const driver = createDidVhDriver({
      loadLog: async () => ({ didLog: logToJsonlString(f.log) }),
      verifier: f.verifier,
    });
    await expect(driver.get({ did: f.did })).resolves.toMatchObject({ id: f.did });
  });

  test('get() reports a DID with no log source as notFound', async () => {
    const f = await createVhFixture();
    const expected = {
      name: 'DIDResolutionError',
      code: 'notFound',
      message: expect.stringContaining('src'),
      problemDetails: { type: 'https://w3id.org/security#NOT_FOUND' },
    };
    await expect(createDidVhDriver({ verifier: f.verifier }).get({ did: f.did })).rejects.toMatchObject(expected);
    for (const stored of [undefined, null, { didLog: '' }, { didLog: ' \n' }]) {
      const driver = createDidVhDriver({ loadLog: async () => stored, verifier: f.verifier });
      await expect(driver.get({ did: f.did })).rejects.toMatchObject(expected);
    }
  });

  test('a loadLog rejection is internalError', async () => {
    const f = await createVhFixture();
    const loadLog = async () => {
      throw new Error('ECONNREFUSED db');
    };
    const driver = createDidVhDriver({ loadLog, verifier: f.verifier });

    await expect(driver.get({ did: f.did })).rejects.toMatchObject({
      name: 'DIDResolutionError',
      code: 'internalError',
      message: expect.stringContaining('ECONNREFUSED db'),
      problemDetails: { type: 'https://www.w3.org/ns/did#INTERNAL_ERROR' },
    });
    const result = await driver.resolveDID({ did: f.did });
    expect(result.didResolutionMetadata.error).toBe('internalError');
  });

  test('get() retrieves the log from the src parameter when loadLog has none', async () => {
    stubGlobalFetchUnused();
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ 'https://example.com/dids/did.jsonl': logToJsonlString(f.log) });
    const loadLog = vi.fn(async () => undefined);
    const driver = createDidVhDriver({ loadLog, verifier: f.verifier, fetch });

    const src = encodeURIComponent('https://example.com/dids');
    const doc = await driver.get({ url: `${f.did}?src=${src}` });
    expect(doc.id).toBe(f.did);
    expect(seen).toEqual(['https://example.com/dids/did.jsonl']);
    expect(loadLog).toHaveBeenCalledWith({ did: f.did });
    expect(globalThis.fetch).not.toHaveBeenCalled();

    const fragment = f.log[0].state.verificationMethod![0].id!.split('#')[1];
    const node = await driver.get({ url: `${f.did}?src=${src}#${fragment}` });
    expect(node).toMatchObject({ publicKeyMultibase: f.key.publicKeyMultibase });
  });

  test('get() uses the log from loadLog for a URL with a src parameter', async () => {
    stubGlobalFetchUnused();
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({});
    const driver = createDidVhDriver({
      loadLog: storedLog(f.did, f.log),
      verifier: f.verifier,
      fetch,
      network: 'none',
    });

    const doc = await driver.get({ url: `${f.did}?src=${encodeURIComponent('https://example.com/dids')}` });
    expect(doc.id).toBe(f.did);
    expect(seen).toEqual([]);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('get() refuses a loopback http or file: src', async () => {
    const f = await createVhFixture();
    const driver = createDidVhDriver({ verifier: f.verifier });
    for (const src of ['http://localhost:3000/x', 'file:///tmp/x']) {
      await expect(driver.get({ url: `${f.did}?src=${encodeURIComponent(src)}` })).rejects.toMatchObject({
        code: 'invalidDidUrl',
        problemDetails: { type: 'https://www.w3.org/ns/did#INVALID_DID_URL' },
      });
    }
  });

  test('get() reports a src location with no log as notFound', async () => {
    const f = await createVhFixture();
    const { fetch } = createUrlFetch({});
    const driver = createDidVhDriver({ verifier: f.verifier, fetch });
    await expect(
      driver.get({ url: `${f.did}?src=${encodeURIComponent('https://example.com/dids')}` })
    ).rejects.toMatchObject({
      name: 'DIDResolutionError',
      code: 'notFound',
    });
  });

  test('get() dereferences verification-method and service fragments', async () => {
    const service = { id: '{DID}#files', type: 'Example', serviceEndpoint: 'https://files.example' };
    const f = await createVhFixture({ services: [service] });
    const driver = createDidVhDriver({ loadLog: storedLog(f.did, f.log), verifier: f.verifier });

    const vmId = f.log[0].state.verificationMethod![0].id!;
    const vm = await driver.get({ url: vmId });
    expect(vm).toMatchObject({ id: vmId, '@context': 'https://w3id.org/security/multikey/v1' });

    const node = await driver.get({ url: `${f.did}#files` });
    expect(node).toMatchObject({ ...service, id: `${f.did}#files` });

    await expect(driver.get({ url: `${f.did}#missing` })).rejects.toMatchObject({
      name: 'VerificationMethodError',
      code: 'notFound',
      verificationMethod: `${f.did}#missing`,
    });
  });

  test('get() dereferences a versioned URL in the document at that version', async () => {
    const f = await createVhFixture({
      services: [{ id: '{DID}#files', type: 'Example', serviceEndpoint: 'https://files.example' }],
    });
    // The update replaces the service list.
    const { log } = await updateDID({
      log: f.log,
      signer: f.signer,
      verifier: f.verifier,
      updated: nextSecond(f.log),
      services: [{ id: `${f.did}#other`, type: 'Example', serviceEndpoint: 'https://other.example' }],
    });
    const driver = createDidVhDriver({ loadLog: storedLog(f.did, log), verifier: f.verifier });

    const atOne = await driver.get({ url: `${f.did}?versionNumber=1#files` });
    expect(atOne).toMatchObject({ id: `${f.did}#files` });
    await expect(driver.get({ url: `${f.did}#files` })).rejects.toMatchObject({ code: 'notFound' });
  });

  test('get() rejects a log whose last entry fails verification', async () => {
    const f = await createThreeEntryVh();
    const log = withCorruptTail(f.log);
    const driver = createDidVhDriver({ loadLog: storedLog(f.did, log), verifier: f.verifier });

    await expect(driver.get({ did: f.did })).rejects.toMatchObject({
      name: 'DIDResolutionError',
      code: 'invalidDid',
      message: expect.stringContaining('Entries after version 2 failed verification'),
      problemDetails: { detail: expect.stringContaining('Entries after version 2') },
    });
    // A version parameter that picks a valid entry returns that version.
    const first = await driver.get({ url: `${f.did}?versionNumber=1` });
    expect(first.id).toBe(f.did);
    await expect(driver.get({ url: `${f.did}?versionNumber=3` })).rejects.toMatchObject({ code: 'invalidDid' });
    // The non-throwing form keeps the resolver's answer: the last valid document and a warning.
    const result = await driver.resolveDID({ did: f.did });
    expect(result.didDocument?.id).toBe(f.did);
    expect(result.didResolutionMetadata.warnings).toMatchObject([{ code: 'invalid-entries' }]);
  });

  test('get() rejects with invalidDid when the witness threshold is not met', async () => {
    const f = await createWitnessedVh();
    const driver = createDidVhDriver({ loadLog: storedLog(f.did, f.log), verifier: f.verifier });
    await expect(driver.get({ did: f.did })).rejects.toMatchObject({
      code: 'invalidDid',
      message: expect.stringContaining('Witness threshold not met'),
    });
  });

  test('get() resolves a witnessed DID with the witness proofs loadLog returns', async () => {
    stubGlobalFetchUnused();
    const f = await createWitnessedVh();
    const driver = createDidVhDriver({ loadLog: storedLog(f.did, f.log, f.didWitness), verifier: f.verifier });
    await expect(driver.get({ did: f.did })).resolves.toMatchObject({ id: f.did });
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('loadLog is not called for a DID URL path or a malformed DID', async () => {
    const f = await createVhFixture();
    const loadLog = storedLog(f.did, f.log);
    const driver = createDidVhDriver({ loadLog, verifier: f.verifier });

    await expect(driver.get({ url: `${f.did}/whois` })).rejects.toMatchObject({
      code: 'notFound',
      message: expect.stringContaining('no DID URL path handling'),
    });
    await expect(driver.get({ url: 'did:vh:x/../../../../some/dir/name#key' })).rejects.toMatchObject({
      name: 'DIDResolutionError',
    });
    await expect(driver.get({ did: 'did:vh:not a scid' })).rejects.toMatchObject({ code: 'invalidDid' });
    await expect(driver.get({ url: `${f.did}?service=files` })).rejects.toMatchObject({ code: 'invalidDidUrl' });
    expect(loadLog).not.toHaveBeenCalled();
  });

  test('resolveDID() returns the result envelope and does not throw', async () => {
    const f = await createThreeEntryVh();
    const driver = createDidVhDriver({ loadLog: storedLog(f.did, f.log), verifier: f.verifier });

    const latest = await driver.resolveDID({ did: f.did });
    expect(latest.didDocument?.id).toBe(f.did);
    expect(latest.didDocumentMetadata.versionId).toBe(f.log[2].versionId);

    const first = await driver.resolveDID({ did: f.did, versionNumber: 1 });
    expect(first.didDocumentMetadata.versionId).toBe(f.log[0].versionId);

    const missing = await createDidVhDriver({ verifier: f.verifier }).resolveDID({ did: f.did });
    expect(missing.didDocument).toBeNull();
    expect(missing.didResolutionMetadata.error).toBe('notFound');

    const badFetch = await driver.resolveDID({ did: f.did, fetch: 'nope' });
    expect(badFetch.didResolutionMetadata.error).toBe('invalidOptions');
  });
});
