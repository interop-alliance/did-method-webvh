/**
 * Default verification-method resolver for proof verification.
 *
 * Method-layer module: resolving a `did:webvh` verification method requires
 * fetching and fully resolving its DID log, so this sits above the resolution
 * engine and is injected downward (`documentStateIsValid`,
 * `countVerifiedWitnessApprovals` take the resolver as an option) instead of
 * the shared bottom modules importing the top of the stack.
 */
import { findVerificationMethod } from './did-document.js';
import type { ResolveVerificationMethod, VerificationMethod } from './interfaces.js';
import { resolveV1Log } from './method_versions/method.v1.0.resolution.js';
import { fetchLogFromIdentifier, parseDidKeyVerificationMethod } from './utils.js';
import { defaultWebvhLogVerifier } from './verifier.js';

const resolveWebvhVM = async (vm: string, resolveVM: ResolveVerificationMethod): Promise<VerificationMethod | null> => {
  const logEntries = await fetchLogFromIdentifier(vm.split('#')[0]);
  const { doc } = await resolveV1Log(logEntries, {
    verificationMethod: vm,
    verifier: defaultWebvhLogVerifier,
    resolveVM,
  });
  if (!doc) {
    throw new Error(`Verification method ${vm} not found`);
  }
  return findVerificationMethod(doc, vm);
};

/**
 * Creates a verification-method resolver whose `did:webvh` memo is private to
 * the returned instance. The method layer creates one per resolution: each
 * `did:webvh` VM is fetched and log-resolved at most once within that
 * resolution (a miss costs a network fetch plus a full log resolution), but
 * nothing is trusted across resolutions, so a rotated or revoked key is
 * picked up by the next resolution. `did:key` lookups are pure parsing and
 * need no memo.
 */
export const createResolveVM = (): ResolveVerificationMethod => {
  // Keyed by promise so concurrent lookups of the same VM dedupe; a rejected
  // lookup is evicted so a transient fetch failure is not memoized.
  const memo = new Map<string, Promise<VerificationMethod | null>>();

  const resolve: ResolveVerificationMethod = async (vm: string) => {
    try {
      if (vm.startsWith('did:key:')) {
        const parsedVerificationMethod = parseDidKeyVerificationMethod(vm);
        return { publicKeyMultibase: parsedVerificationMethod.keyMultibase };
      } else if (vm.startsWith('did:webvh:')) {
        let pending = memo.get(vm);
        if (!pending) {
          pending = resolveWebvhVM(vm, resolve);
          memo.set(vm, pending);
          pending.catch(() => memo.delete(vm));
        }
        return await pending;
      }
      throw new Error(`Verification method ${vm} not found`);
    } catch {
      throw new Error(`Error resolving VM ${vm}`);
    }
  };

  return resolve;
};

/** Standalone default resolver: a fresh single-use memo per call. */
export const resolveVM: ResolveVerificationMethod = (vm: string) => createResolveVM()(vm);
