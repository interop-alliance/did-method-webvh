/**
 * did-io-compatible did:vh driver for JSON-LD document loaders, exported as
 * the `/vh/driver` subpath.
 *
 * A did:vh DID names no location, so the driver needs a log source. It asks
 * the caller-supplied `loadLog` callback first, which reads the log from
 * wherever the caller keeps it (local storage, a cache, a registry). When
 * the callback has no log, a DID URL carrying the `src` parameter is
 * retrieved from the location it names.
 *
 * The returned driver is a plain object literal shaped
 * `{ method, get({ did, url }), resolveDID({ did }) }`. This module imports
 * nothing from did-io.
 */
import { DIDResolutionError, type IDIDResolutionResult } from '@interop/data-integrity-core';
import { narrowDriverOptions, requireFragmentNode, requireResolvedDocument } from './driver-shared.js';
import type { DIDDoc, DIDLog, FetchLike, Verifier, WitnessProofFileEntry } from './interfaces.js';
import { INVALID_ENTRIES_WARNING, thrownToVhResult, toErrorMeta } from './resolver-result.js';
import { parseDidVhIdentifier } from './utils/did-vh-identifier.js';
import { resolveDID, type VhResolutionOptions } from './vh.js';
import { applyVhDidUrl, parseVhDidUrl } from './vh-did-url.js';

/**
 * Builds a did-io-compatible `did:vh` driver for a document loader's
 * resolver. A bare DID resolves to its DID document. A `did#fragment` URL is
 * dereferenced to its verification-method (or service) node. The URL may
 * carry `src` and one of `versionId`, `versionTime` and `versionNumber`.
 *
 * `loadLog` is asked first. It is called only with a syntactically valid
 * `did:vh:<scid>`, so it may use the DID to build a storage key. It returns
 * the log as `didLog` and, for a DID that requires witnesses, the witness
 * proofs file as `didWitness`. When it has no log (it returns `undefined`,
 * `null`, or an empty log text), the log is retrieved from the `src`
 * parameter of the URL. With neither, resolution fails with `notFound`. A
 * rejection from `loadLog` is reported as `internalError`.
 *
 * `get()` throws a `DIDResolutionError` (from `@interop/data-integrity-core`)
 * carrying the resolution error `code` and RFC 9457 `problemDetails`. With no
 * version parameter in the URL it also throws one, with code `invalidDid`,
 * when entries at the end of the log fail verification. The did:vh resolver
 * reports those as an `invalid-entries` warning next to the last valid
 * document, and a loader consumer asking for the current document must not
 * receive an out-of-date one. A URL whose version parameter picks a valid
 * entry returns that version. A fragment that names no node in the resolved
 * document throws a `VerificationMethodError` with code `notFound` and the
 * requested DID URL in `verificationMethod`.
 *
 * The driver's `resolveDID()` is the non-throwing form: it returns the DID
 * Resolution result envelope of this package's did:vh {@link resolveDID},
 * warnings included.
 *
 * @param options Driver options.
 * @param [options.loadLog] Returns the log of a DID as JSON Lines text or
 *   parsed entries in `didLog`, with its witness proofs file (the parsed
 *   JSON array) in `didWitness` when it has one. Returns `undefined` or `null` when
 *   the caller has no log.
 * @param [options.verifier] Verifier for the log's proofs. Defaults to the
 *   package's Ed25519 verifier.
 * @param [options.fetch] Fetch override for a `src` location. Defaults to
 *   the global `fetch`.
 * @param [options.network] Which network requests a resolution may make.
 * @returns A `{ method, get, resolveDID }` driver.
 */
export function createDidVhDriver({
  loadLog,
  verifier,
  fetch: fetchFn,
  network,
}: {
  loadLog?: (options: {
    did: string;
  }) => Promise<{ didLog: string | DIDLog; didWitness?: WitnessProofFileEntry[] } | null | undefined>;
  verifier?: Verifier;
  fetch?: FetchLike;
  network?: VhResolutionOptions['network'];
} = {}): {
  method: string;
  get(options: { did?: string; url?: string }): Promise<DIDDoc | Record<string, unknown>>;
  resolveDID(options: { did: string; [key: string]: unknown }): Promise<IDIDResolutionResult>;
} {
  /** Asks `loadLog` for the log of `did`. Returns `undefined` when it has none. */
  async function loadStoredLog(did: string): Promise<Pick<VhResolutionOptions, 'didLog' | 'didWitness'> | undefined> {
    let stored: Awaited<ReturnType<NonNullable<typeof loadLog>>>;
    try {
      stored = await loadLog?.({ did });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new DIDResolutionError(`loadLog failed for "${did}": ${reason}`, { code: 'internalError', cause: error });
    }
    const didLog = stored?.didLog;
    if (didLog == null || (typeof didLog === 'string' && didLog.trim() === '')) {
      return undefined;
    }
    return { didLog, didWitness: stored?.didWitness ?? undefined };
  }

  /**
   * Resolves a DID URL, taking the log from `loadLog` or from `src`. Does
   * not throw: a failure is returned as an error result. `parsed` holds the
   * parts of the URL when it parsed.
   */
  async function resolveUrl(
    didUrl: string,
    perCall: VhResolutionOptions = {}
  ): Promise<{ result: IDIDResolutionResult; parsed?: ReturnType<typeof parseVhDidUrl> }> {
    let parsed: ReturnType<typeof parseVhDidUrl> | undefined;
    try {
      parsed = parseVhDidUrl(didUrl);
      const { did } = parsed;
      // The DID is validated before it reaches the callback. A malformed one
      // throws a plain `Error`, which is reported as `invalidDid`.
      parseDidVhIdentifier(did, 'did');
      const stored = await loadStoredLog(did);
      if (!stored && !parsed.derived) {
        throw new DIDResolutionError(
          `No DID log source for "${did}". Name the log location with the src DID URL parameter (did:vh:<scid>?src=https://example.com/path).`,
          { code: 'notFound' }
        );
      }
      const options = applyVhDidUrl(parsed, { verifier, fetch: fetchFn, network, ...perCall, ...stored });
      return { result: await resolveDID(did, options), parsed };
    } catch (error) {
      return { result: thrownToVhResult(error), parsed };
    }
  }

  return {
    method: 'vh',
    async get({ did, url } = {}): Promise<DIDDoc | Record<string, unknown>> {
      const didOrUrl = did ?? url;
      if (!didOrUrl) {
        throw new TypeError('A DID or a URL is required to resolve.');
      }
      const { result, parsed } = await resolveUrl(didOrUrl);
      const doc = requireResolvedDocument(result, didOrUrl);
      const warnings = (result.didResolutionMetadata.warnings ?? []) as { code: string; message: string }[];
      const invalidEntries = warnings.find((warning) => warning.code === INVALID_ENTRIES_WARNING);
      // An explicitly selected version is the one the caller asked for.
      if (invalidEntries && Object.keys(parsed?.selectors ?? {}).length === 0) {
        const { error: code, problemDetails } = toErrorMeta('invalidDid', invalidEntries.message);
        throw new DIDResolutionError(invalidEntries.message, { code, problemDetails });
      }
      return parsed?.fragment ? requireFragmentNode(doc, parsed.fragment, didOrUrl) : doc;
    },
    async resolveDID({ did, ...options }: { did: string; [key: string]: unknown }): Promise<IDIDResolutionResult> {
      const { error, fetch: perCallFetch, selectors } = narrowDriverOptions(options);
      if (error) {
        return error;
      }
      const { result } = await resolveUrl(did, { ...selectors, fetch: perCallFetch ?? fetchFn });
      return result;
    },
  };
}
