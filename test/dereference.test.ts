import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import { dereferenceVerificationMethod, parseVerificationMethodUrl } from '../src/dereference.js';
import type { DIDLog, VerificationMethod } from '../src/interfaces.js';
import { createDID, updateDID } from '../src/method.js';
import { createResolveVM } from '../src/vm-resolver.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
  nextSecond,
  stubGlobalFetchUnused,
} from './utils.js';

// A three-version log: v1 carries authKey, v2 adds key2, v3 adds key3.
let did: string;
let log: DIDLog;
let key2: VerificationMethod;
let key3: VerificationMethod;
let key2Id: string;
let key3Id: string;

const fragmentOf = (id: string) => id.slice(id.indexOf('#') + 1);

beforeAll(async () => {
  const authKey = await generateTestVerificationMethod();
  key2 = await generateTestVerificationMethod('assertionMethod');
  key3 = await generateTestVerificationMethod('assertionMethod');
  const signer = createTestSigner(authKey);
  const verifier = createTestVerifier(authKey);

  const created = await createDID({
    address: 'example.com',
    signer,
    verifier,
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
  });
  const v2 = await updateDID({
    log: created.log,
    updated: nextSecond(created.log),
    signer,
    verifier,
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey, key2),
  });
  const v3 = await updateDID({
    log: v2.log,
    updated: nextSecond(v2.log),
    signer,
    verifier,
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey, key2, key3),
  });

  did = created.did;
  log = v3.log;
  key2Id = log[1].state.verificationMethod!.find((vm) => vm.publicKeyMultibase === key2.publicKeyMultibase)!.id!;
  key3Id = log[2].state.verificationMethod!.find((vm) => vm.publicKeyMultibase === key3.publicKeyMultibase)!.id!;
});

describe('parseVerificationMethodUrl', () => {
  test('parses a versioned verification-method DID URL', () => {
    expect(parseVerificationMethodUrl('did:webvh:abc:example.com?versionId=2-xyz#key-1')).toEqual({
      did: 'did:webvh:abc:example.com',
      versionId: '2-xyz',
      fragment: 'key-1',
    });
  });

  test('parses an unversioned verification-method DID URL', () => {
    expect(parseVerificationMethodUrl('did:webvh:abc:example.com#key-1')).toEqual({
      did: 'did:webvh:abc:example.com',
      versionId: undefined,
      fragment: 'key-1',
    });
  });

  test('a URL with no fragment yields an undefined fragment', () => {
    expect(parseVerificationMethodUrl('did:webvh:abc:example.com?versionId=1-xyz')).toEqual({
      did: 'did:webvh:abc:example.com',
      versionId: '1-xyz',
      fragment: undefined,
    });
  });

  test('throws on an empty query', () => {
    expect(() => parseVerificationMethodUrl('did:webvh:abc:example.com?#key-1')).toThrow(/Empty query/);
  });

  test('throws on a valueless or empty versionId', () => {
    expect(() => parseVerificationMethodUrl('did:webvh:abc:example.com?versionId#key-1')).toThrow(
      /Empty DID parameter 'versionId'/
    );
    expect(() => parseVerificationMethodUrl('did:webvh:abc:example.com?versionId=#key-1')).toThrow(
      /Empty DID parameter 'versionId'/
    );
  });

  test('throws on an unsupported DID parameter', () => {
    expect(() =>
      parseVerificationMethodUrl('did:webvh:abc:example.com?versionTime=2024-01-01T00:00:00Z#key-1')
    ).toThrow(/Unsupported DID parameter 'versionTime'/);
  });

  test('throws on a repeated versionId parameter', () => {
    expect(() => parseVerificationMethodUrl('did:webvh:abc:example.com?versionId=1-a&versionId=2-b#key-1')).toThrow(
      /Repeated DID parameter 'versionId'/
    );
  });
});

describe('dereferenceVerificationMethod', () => {
  test('returns the member in the document at the requested version', () => {
    const vm = dereferenceVerificationMethod(log, `${did}?versionId=${log[1].versionId}#${fragmentOf(key2Id)}`);
    const expected = log[1].state.verificationMethod!.find((member) => member.id === key2Id);
    expect(vm).toEqual(expected);
    expect(vm?.publicKeyMultibase).toBe(key2.publicKeyMultibase);
  });

  test('returns null when the member is absent at the requested version', () => {
    expect(dereferenceVerificationMethod(log, `${did}?versionId=${log[0].versionId}#${fragmentOf(key2Id)}`)).toBeNull();
    expect(dereferenceVerificationMethod(log, `${did}?versionId=${log[1].versionId}#${fragmentOf(key3Id)}`)).toBeNull();
  });

  test('returns null for a fragment naming no member', () => {
    expect(dereferenceVerificationMethod(log, `${did}?versionId=${log[1].versionId}#no-such-key`)).toBeNull();
    expect(dereferenceVerificationMethod(log, `${did}#no-such-key`)).toBeNull();
  });

  test('returns null for an unknown versionId', () => {
    expect(dereferenceVerificationMethod(log, `${did}?versionId=9-unknown#${fragmentOf(key2Id)}`)).toBeNull();
  });

  test('returns null for a URL with no fragment', () => {
    expect(dereferenceVerificationMethod(log, `${did}?versionId=${log[1].versionId}`)).toBeNull();
  });

  test('returns null for an empty log', () => {
    expect(dereferenceVerificationMethod([], `${did}#${fragmentOf(key2Id)}`)).toBeNull();
  });

  test('an unversioned URL dereferences against the latest document', () => {
    const vm = dereferenceVerificationMethod(log, key3Id);
    expect(vm?.publicKeyMultibase).toBe(key3.publicKeyMultibase);
  });

  test('throws on an unsupported DID parameter', () => {
    expect(() =>
      dereferenceVerificationMethod(log, `${did}?versionTime=2024-01-01T00:00:00Z#${fragmentOf(key2Id)}`)
    ).toThrow(/Unsupported DID parameter/);
  });
});

describe('createResolveVM with versioned DID URLs', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test('resolves a versioned URL to the member at that version', async () => {
    stubGlobalFetchUnused();
    const resolveControlledDid = vi.fn(async (requested: string) => (requested === did ? log : undefined));
    const resolve = createResolveVM({ resolveControlledDid });

    const vm = await resolve(`${did}?versionId=${log[1].versionId}#${fragmentOf(key2Id)}`);

    expect(vm).toMatchObject({ id: key2Id, publicKeyMultibase: key2.publicKeyMultibase });
    expect(resolveControlledDid).toHaveBeenCalledWith(did);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  test('rejects a versioned URL whose member is absent at an existing version', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => log });
    const vmUrl = `${did}?versionId=${log[0].versionId}#${fragmentOf(key2Id)}`;

    await expect(resolve(vmUrl)).rejects.toThrow(`Error resolving VM ${vmUrl}`);
  });

  test('rejects a versioned URL with no fragment', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => log });
    const vmUrl = `${did}?versionId=${log[1].versionId}`;

    await expect(resolve(vmUrl)).rejects.toThrow(`Error resolving VM ${vmUrl}`);
  });

  test('returns a copy, not a reference into the loaded log', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => log });

    const vm = await resolve(`${did}?versionId=${log[1].versionId}#${fragmentOf(key2Id)}`);

    const member = log[1].state.verificationMethod!.find((candidate) => candidate.id === key2Id);
    expect(vm).toEqual(member);
    expect(vm).not.toBe(member);
  });

  test('loads the log once for the versioned and unversioned forms of one DID', async () => {
    const resolveControlledDid = vi.fn(async () => log);
    const resolve = createResolveVM({ resolveControlledDid });

    await resolve(key3Id);
    await resolve(`${did}?versionId=${log[1].versionId}#${fragmentOf(key2Id)}`);
    await resolve(`${did}?versionId=${log[2].versionId}#${fragmentOf(key3Id)}`);

    expect(resolveControlledDid).toHaveBeenCalledTimes(1);
  });

  test('rejects a versioned URL naming a version that does not exist', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => log });
    const vmUrl = `${did}?versionId=9-unknown#${fragmentOf(key2Id)}`;

    await expect(resolve(vmUrl)).rejects.toThrow(`Error resolving VM ${vmUrl}`);
  });

  test('rejects a URL with an unsupported DID parameter', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => log });
    const vmUrl = `${did}?versionTime=2024-01-01T00:00:00Z#${fragmentOf(key2Id)}`;

    await expect(resolve(vmUrl)).rejects.toThrow(`Error resolving VM ${vmUrl}`);
  });

  test('still resolves an unversioned URL', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => log });

    const vm = await resolve(key3Id);

    expect(vm?.publicKeyMultibase).toBe(key3.publicKeyMultibase);
  });
});

describe('versioned DID URLs of a portable DID that moved', () => {
  // v1 under example.com carries authKey and movedKey; v2 moves to
  // example.org and drops movedKey.
  let originalDid: string;
  let movedDid: string;
  let movedLog: DIDLog;
  let movedKey: VerificationMethod;
  let movedKeyFragment: string;

  beforeAll(async () => {
    const authKey = await generateTestVerificationMethod();
    movedKey = await generateTestVerificationMethod('assertionMethod');
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const created = await createDID({
      address: 'example.com',
      portable: true,
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey, movedKey),
    });
    const moved = await updateDID({
      log: created.log,
      updated: nextSecond(created.log),
      address: 'example.org',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    originalDid = created.did;
    movedDid = moved.did;
    movedLog = moved.log;
    const movedKeyId = movedLog[0].state.verificationMethod!.find(
      (vm) => vm.publicKeyMultibase === movedKey.publicKeyMultibase
    )!.id!;
    movedKeyFragment = fragmentOf(movedKeyId);
    expect(movedDid).not.toBe(originalDid);
  });

  test('dereferenceVerificationMethod finds a pre-move member under the current DID', () => {
    const vm = dereferenceVerificationMethod(
      movedLog,
      `${movedDid}?versionId=${movedLog[0].versionId}#${movedKeyFragment}`
    );
    expect(vm?.id).toBe(`${originalDid}#${movedKeyFragment}`);
    expect(vm?.publicKeyMultibase).toBe(movedKey.publicKeyMultibase);
  });

  test('createResolveVM finds a pre-move member under the current DID', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => movedLog });

    const vm = await resolve(`${movedDid}?versionId=${movedLog[0].versionId}#${movedKeyFragment}`);

    expect(vm).toMatchObject({
      id: `${originalDid}#${movedKeyFragment}`,
      publicKeyMultibase: movedKey.publicKeyMultibase,
    });
  });

  test('createResolveVM rejects a URL naming a DID the log never carried', async () => {
    const resolve = createResolveVM({ resolveControlledDid: async () => movedLog });
    const vmUrl = `did:webvh:${movedDid.split(':')[2]}:elsewhere.example?versionId=${movedLog[0].versionId}#${movedKeyFragment}`;

    await expect(resolve(vmUrl)).rejects.toThrow(`Error resolving VM ${vmUrl}`);
  });
});
