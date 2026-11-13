import type { Mock } from 'vitest';
import { vi } from 'vitest';
import type { DIDLog, FetchLike, VerificationMethod } from '../src/interfaces.js';
import { createDID, updateDID } from '../src/vh.js';
import { createWitnessProof } from '../src/witness.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  createWitnessSigner,
  generateTestVerificationMethod,
  nextSecond,
  witnessVerificationMethod,
} from './utils.js';

/** A did:vh DID controlled by a fresh key, returned with the key's signer and verifier. */
export const createVhFixture = async (overrides: Partial<Parameters<typeof createDID>[0]> = {}) => {
  const key = await generateTestVerificationMethod();
  const signer = createTestSigner(key);
  const verifier = createTestVerifier(key);
  const updateKeys = [key.publicKeyMultibase!];
  const created = await createDID({
    signer,
    verifier,
    updateKeys,
    verificationMethods: asPublicVerificationMethods(key),
    ...overrides,
  });
  return { key, signer, verifier, updateKeys, ...created };
};

/** Appends one update that adds a service named `id`. */
export const appendService = async (
  fixture: Pick<Awaited<ReturnType<typeof createVhFixture>>, 'signer' | 'verifier'>,
  log: DIDLog,
  id: string
) => {
  const updated = await updateDID({
    log,
    signer: fixture.signer,
    verifier: fixture.verifier,
    updated: nextSecond(log),
    services: [{ id: `#${id}`, type: 'Example', serviceEndpoint: `https://${id}.example` }],
  });
  return updated.log;
};

/** A fixture and a three-entry log of it. */
export const createThreeEntryVh = async () => {
  const fixture = await createVhFixture();
  const log2 = await appendService(fixture, fixture.log, 'one');
  const log3 = await appendService(fixture, log2, 'two');
  return { ...fixture, log: log3 };
};

/** Creates a did:vh DID that requires `threshold` of `witnesses` (the controller's key is the first). */
export const createWitnessedVh = async (threshold = 1, witnessCount = 1) => {
  const witnessKeys: VerificationMethod[] = [];
  for (let i = 0; i < witnessCount; i++) {
    witnessKeys.push(await generateTestVerificationMethod());
  }
  const fixture = await createVhFixture({
    witness: { threshold, witnesses: witnessKeys.map((k) => ({ id: `did:key:${k.publicKeyMultibase}` })) },
  });
  const proofsFor = async (versionId: string, keys: VerificationMethod[] = witnessKeys) => ({
    versionId,
    proof: await Promise.all(
      keys.map((k) => createWitnessProof(createWitnessSigner(k), versionId, witnessVerificationMethod(k)))
    ),
  });
  const didWitness = [await proofsFor(fixture.log[0].versionId)];
  return { ...fixture, witnessKeys, proofsFor, didWitness };
};

/**
 * A fetch that serves `routes` by exact URL, answers 404 for anything else,
 * and records every URL it was asked for.
 */
export const createUrlFetch = (routes: Record<string, string>): { fetch: Mock & FetchLike; seen: string[] } => {
  const seen: string[] = [];
  const fetch = vi.fn(async (url: string) => {
    seen.push(url);
    const body = routes[url];
    return body === undefined ? new Response('', { status: 404 }) : new Response(body);
  }) as unknown as Mock & FetchLike;
  return { fetch, seen };
};
