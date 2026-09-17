import { beforeAll, describe, expect, test } from 'vitest';
import type { CreateDIDResult, DIDLog, VerificationMethod } from '../src/interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  nextSecond,
  TestCryptoImplementation,
} from './utils.js';

describe('Portability', () => {
  let authKey: VerificationMethod;
  let testImplementation: TestCryptoImplementation;
  let nonPortableDID: CreateDIDResult;
  let portableDID: CreateDIDResult;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey });

    nonPortableDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    portableDID = await createDID({
      address: 'example.com',
      portable: true,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
  });

  test('Rejects setting portable: true in a later entry', async () => {
    const updateResult = await updateDID({
      log: nonPortableDID.log,
      updated: nextSecond(nonPortableDID.log),
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.portable = true;

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      'cannot set portable: true'
    );
  });

  test('updateDID rejects portable: true as an option', async () => {
    await expect(
      updateDID({
        log: nonPortableDID.log,
        portable: true,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('portable: true cannot be set in an update entry');
  });

  test('Rejects false-to-true portable transition (portable was explicitly false)', async () => {
    // Create a DID with portable: false explicitly in the first entry
    const did = await createDID({
      address: 'example.com',
      portable: false,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const updateResult = await updateDID({
      log: did.log,
      updated: nextSecond(did.log),
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    // Tamper: try to re-enable portable in a later entry
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.portable = true;

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      'cannot set portable: true'
    );
  });

  test('Setting portable: false in a later entry permanently locks portability', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      address: 'example.com',
      portable: false,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    // The log entry must carry portable: false in its parameters
    expect(updateResult.log[1].parameters.portable).toBe(false);
    // The returned meta must reflect the lock immediately
    expect(updateResult.meta.portable).toBe(false);

    // Resolution must succeed and report the lock
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.meta.portable).toBe(false);

    // A subsequent move attempt must be rejected
    await expect(
      updateDID({
        log: updateResult.log,
        address: 'example.org',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('Cannot move DID: portability is disabled');
  });

  test('Rejects SCID change in state.id during portable rename', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const originalScid = portableDID.log[0].parameters.scid as string;
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));

    // Replace SCID in state.id with a different value
    const fakeScid = `${originalScid.slice(0, -4)}XXXX`;
    tamperedLog[1].state.id = (tamperedLog[1].state.id as string).replace(originalScid, fakeScid);

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      'does not match SCID in log'
    );
  });

  test('Portable DID moves to a new domain via the address option', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      address: 'example.org',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const originalDid = portableDID.log[0].state.id as string;
    const scid = originalDid.split(':')[2];

    // The new entry's state.id must reflect the new location, same SCID
    expect(updateResult.log[1].state.id).toBe(`did:webvh:${scid}:example.org`);
    expect(updateResult.log[1].state.alsoKnownAs).toContain(originalDid);

    // And it must resolve to the moved DID
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.did).toBe(`did:webvh:${scid}:example.org`);
    expect(resolved.doc?.id).toBe(`did:webvh:${scid}:example.org`);
    expect(resolved.doc?.alsoKnownAs).toContain(originalDid);
  });

  test('Non-portable DID rejects a move to a new domain', async () => {
    await expect(
      updateDID({
        log: nonPortableDID.log,
        updated: nextSecond(nonPortableDID.log),
        address: 'example.org',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      })
    ).rejects.toThrow('Cannot move DID: portability is disabled');
  });

  test('Re-passing a bare domain on a pathed DID preserves the paths', async () => {
    const pathedDID = await createDID({
      address: 'example.com',
      paths: ['dids', 'alice'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Caller threads the same domain through the update but omits paths.
    const updateResult = await updateDID({
      log: pathedDID.log,
      updated: nextSecond(pathedDID.log),
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    expect(updateResult.log[1].state.id).toBe(pathedDID.did);
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.did).toBe(pathedDID.did);
  });

  test('Portable DID moves to a pathed location via the address option', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      address: 'https://example.org/dids/alice',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const scid = (portableDID.log[0].state.id as string).split(':')[2];
    expect(updateResult.log[1].state.id).toBe(`did:webvh:${scid}:example.org:dids:alice`);
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.did).toBe(`did:webvh:${scid}:example.org:dids:alice`);
  });

  test('UpdateDID rejects dot-segment in explicit paths array', async () => {
    await expect(
      updateDID({
        log: portableDID.log,
        address: 'example.org',
        paths: ['..', 'secrets'],
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('updateDID path segments must not contain dot-segments');
  });

  test('UpdateDID rejects encoded slash inside explicit path segment', async () => {
    await expect(
      updateDID({
        log: portableDID.log,
        address: 'example.org',
        paths: ['a%2Fb'],
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('updateDID path segments must not contain decoded slash within a single path segment');
  });
});

describe('Portable move self-reference rewriting', () => {
  const externalDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

  test('rewrites self-referential controller and VM ids, leaving external controllers alone', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);

    const created = await createDID({
      address: 'example.com',
      signer,
      updateKeys: [authKey.publicKeyMultibase!],
      portable: true,
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: '{DID}',
        controller: '{DID}',
        verificationMethod: [
          {
            id: '{DID}#key-1',
            type: 'Multikey',
            controller: '{DID}',
            publicKeyMultibase: authKey.publicKeyMultibase,
          },
          {
            id: `${externalDid}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`,
            type: 'Multikey',
            controller: externalDid,
            publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          },
        ],
        authentication: ['{DID}#key-1'],
      },
    });

    const oldDid = created.did;

    // A move with no document options at all: the carried-forward document is
    // the only thing that can be rewritten.
    const updated = await updateDID({
      log: created.log,
      signer,
      updated: nextSecond(created.log),
      address: 'new-domain.com',
    });

    const newDid = updated.did;
    expect(newDid).toContain('new-domain.com');
    expect(updated.doc.id).toBe(newDid);
    expect(updated.doc.controller).toBe(newDid);
    expect(updated.doc.verificationMethod?.[0].id).toBe(`${newDid}#key-1`);
    expect(updated.doc.verificationMethod?.[0].controller).toBe(newDid);
    expect(updated.doc.authentication).toEqual([`${newDid}#key-1`]);

    // The externally-controlled verification method is untouched.
    expect(updated.doc.verificationMethod?.[1].id).toBe(
      `${externalDid}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`
    );
    expect(updated.doc.verificationMethod?.[1].controller).toBe(externalDid);

    // The predecessor is retained as an alias.
    expect(updated.doc.alsoKnownAs).toContain(oldDid);
  });

  test('rewrites service ids and self-referential service endpoints', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);

    const created = await createDID({
      address: 'example.com',
      signer,
      updateKeys: [authKey.publicKeyMultibase!],
      portable: true,
      verificationMethods: asPublicVerificationMethods(authKey),
      services: [
        {
          id: '{DID}#files',
          type: 'relativeRef',
          serviceEndpoint: 'https://example.com/files',
        },
        {
          id: '{DID}#delegate',
          type: 'Delegation',
          serviceEndpoint: { self: '{DID}/inbox', other: `${externalDid}#key-1` },
        },
      ],
    });

    const updated = await updateDID({
      log: created.log,
      signer,
      updated: nextSecond(created.log),
      address: 'new-domain.com',
    });

    const newDid = updated.did;
    expect(updated.doc.service?.[0].id).toBe(`${newDid}#files`);
    // An endpoint that is not a DID URL of the moved DID is left alone.
    expect(updated.doc.service?.[0].serviceEndpoint).toBe('https://example.com/files');

    expect(updated.doc.service?.[1].id).toBe(`${newDid}#delegate`);
    const endpoint = updated.doc.service?.[1].serviceEndpoint as { self: string; other: string };
    expect(endpoint.self).toBe(`${newDid}/inbox`);
    expect(endpoint.other).toBe(`${externalDid}#key-1`);
  });
});
