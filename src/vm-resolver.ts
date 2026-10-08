/**
 * Default verification-method resolver for proof verification.
 *
 * Method-layer module: resolving a `did:webvh` verification method requires
 * fetching and fully resolving its DID log, so this sits above the resolution
 * engine and is injected downward (`documentStateIsValid`,
 * `countVerifiedWitnessApprovals` take the resolver as an option) instead of
 * the shared bottom modules importing the top of the stack.
 */
import { parseVerificationMethodUrl } from './dereference.js';
import { findVerificationMethod } from './did-document.js';
import type { DIDLog, LogSourceOptions, ResolveVerificationMethod, VerificationMethod } from './interfaces.js';
import { resolveV1Log } from './method_versions/method.v1.0.resolution.js';
import { loadDIDLog, parseDidKeyVerificationMethod } from './utils.js';
import { defaultWebvhLogVerifier } from './verifier.js';

/**
 * Resolves a `did:webvh` verification-method DID URL to its member, or throws
 * when the URL names nothing. The unversioned form (`<did>#<fragment>`) is
 * looked up in the document that contains it. The versioned form
 * (`<did>?versionId=<id>#<fragment>`) resolves the log with the `versionId`
 * selector and dereferences `<document id>#<fragment>` in that version's
 * document. The document id is used rather than the URL's DID because a
 * portable DID's earlier versions carry the earlier DID. The URL's DID must
 * be the selected document's id or a DID the log has since moved from.
 *
 * Resolution processes the whole log. With an explicit version selector, a
 * failure in an entry after the selected one does not reject the selected
 * version (see `resolveV1Log`).
 */
const resolveWebvhVM = async (
  vm: string,
  loadLog: (did: string) => Promise<DIDLog>,
  resolveVM: ResolveVerificationMethod,
  options: LogSourceOptions
): Promise<VerificationMethod> => {
  const { did, versionId, fragment } = parseVerificationMethodUrl(vm);
  const notFound = () => new Error(`Verification method ${vm} not found`);
  if (fragment === undefined) {
    throw notFound();
  }
  const logEntries = await loadLog(did);
  const selector = versionId === undefined ? { verificationMethod: vm } : { versionId };
  const { doc } = await resolveV1Log(logEntries, {
    ...selector,
    verifier: defaultWebvhLogVerifier,
    resolveVM,
    fetch: options.fetch,
  });
  if (!doc) {
    throw notFound();
  }
  let target = vm;
  if (versionId !== undefined) {
    const namesThisLog = did === doc.id || logEntries.some((entry) => entry.state.id === did);
    if (!namesThisLog) {
      throw new Error(`Verification method ${vm} names a DID the resolved log never carried`);
    }
    target = `${doc.id}#${fragment}`;
  }
  const member = findVerificationMethod(doc, target);
  if (!member) {
    throw notFound();
  }
  return member;
};

/**
 * Memoizes `make()` under `key` in `map`, keyed by promise so concurrent
 * lookups dedupe. A rejected promise is evicted so a transient fetch failure
 * is not memoized.
 */
const memoized = <T>(map: Map<string, Promise<T>>, key: string, make: () => Promise<T>): Promise<T> => {
  let pending = map.get(key);
  if (!pending) {
    pending = make();
    map.set(key, pending);
    pending.catch(() => map.delete(key));
  }
  return pending;
};

/**
 * Creates a verification-method resolver whose `did:webvh` memos are private
 * to the returned instance. A `did:webvh` VM may be unversioned
 * (`<did>#<fragment>`) or versioned (`<did>?versionId=<id>#<fragment>`). The
 * loaded log is memoized by bare DID, so the two forms share one fetch; the
 * resolved member is memoized by the full DID URL, since each form selects a
 * different version. The method layer creates one per resolution: each
 * `did:webvh` log is fetched at most once and each VM is log-resolved at most
 * once within that resolution, but nothing is trusted across resolutions, so
 * a rotated or revoked key is picked up by the next resolution. `did:key`
 * lookups are pure parsing and need no memo.
 *
 * @param [options.fetch] Fetch override used to retrieve a `did:webvh` VM's
 *   DID log and `did-witness.json`. Defaults to the global `fetch`.
 * @param [options.resolveControlledDid] Consulted first for a `did:webvh` VM's
 *   DID log; an `undefined` result falls back to fetching. See
 *   {@link ResolutionOptions.resolveControlledDid}.
 */
export const createResolveVM = (options: LogSourceOptions = {}): ResolveVerificationMethod => {
  const logs = new Map<string, Promise<DIDLog>>();
  const members = new Map<string, Promise<VerificationMethod>>();
  const loadLog = (did: string) => memoized(logs, did, () => loadDIDLog(did, options));

  const resolve: ResolveVerificationMethod = async (vm: string) => {
    try {
      if (vm.startsWith('did:key:')) {
        const parsedVerificationMethod = parseDidKeyVerificationMethod(vm);
        return { publicKeyMultibase: parsedVerificationMethod.keyMultibase };
      } else if (vm.startsWith('did:webvh:')) {
        return await memoized(members, vm, () => resolveWebvhVM(vm, loadLog, resolve, options));
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
