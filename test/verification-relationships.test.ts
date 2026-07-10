import { expect, test } from 'vitest';
import { createDID, updateDID } from '../src/method.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
} from './utils.js';

// The `{SCID}` placeholder in a relationship ref is substituted with the real
// SCID by createDID, just like the controller/verificationMethod ids, so a ref
// built against the placeholder resolves to the verification method's id.
function placeholderRef(publicKeyMultibase: string): string {
  return `did:webvh:{SCID}:example.com#${publicKeyMultibase.slice(-8)}`;
}

test('createDID wires capabilityDelegation and capabilityInvocation from options', async () => {
  const authKey = await generateTestVerificationMethod();
  const ref = placeholderRef(authKey.publicKeyMultibase!);

  const { doc } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey),
    verifier: createTestVerifier(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
    authentication: [ref],
    assertionMethod: [ref],
    capabilityDelegation: [ref],
    capabilityInvocation: [ref],
  });

  const vmId = doc.verificationMethod![0].id;
  expect(doc.authentication).toEqual([vmId]);
  expect(doc.assertionMethod).toEqual([vmId]);
  expect(doc.capabilityDelegation).toEqual([vmId]);
  expect(doc.capabilityInvocation).toEqual([vmId]);
});

test('a verification method may declare multiple purposes (referenced by id)', async () => {
  const authKey = await generateTestVerificationMethod([
    'authentication',
    'assertionMethod',
    'capabilityDelegation',
    'capabilityInvocation',
  ]);

  const { doc } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey),
    verifier: createTestVerifier(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
  });

  // The single verification method is referenced from every listed relationship.
  expect(doc.verificationMethod).toHaveLength(1);
  const vmId = doc.verificationMethod![0].id;
  expect(doc.authentication).toEqual([vmId]);
  expect(doc.assertionMethod).toEqual([vmId]);
  expect(doc.capabilityDelegation).toEqual([vmId]);
  expect(doc.capabilityInvocation).toEqual([vmId]);
  expect(doc.keyAgreement ?? []).toEqual([]);
  // `purpose` is a creation directive and must not leak into the DID document.
  expect('purpose' in doc.verificationMethod![0]).toBe(false);
});

test('updateDID wires capabilityDelegation and capabilityInvocation from options', async () => {
  const authKey = await generateTestVerificationMethod();
  const { doc: created, log } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey),
    verifier: createTestVerifier(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
  });

  const vmId = created.verificationMethod![0].id!;
  const { doc } = await updateDID({
    log,
    signer: createTestSigner(authKey),
    verifier: createTestVerifier(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    context: created['@context'],
    verificationMethods: asPublicVerificationMethods(authKey),
    capabilityDelegation: [vmId],
    capabilityInvocation: [vmId],
  });

  expect(doc.capabilityDelegation).toEqual([vmId]);
  expect(doc.capabilityInvocation).toEqual([vmId]);
});
