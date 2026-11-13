import { DIDResolutionError } from '@interop/data-integrity-core';
import type { DIDLog, FetchLike, LogSourceOptions, ResolutionOptions, WitnessProofFileEntry } from './interfaces.js';
import { fetchBounded, toRetrievalError } from './utils/bounded-fetch.js';
import { getFileUrl, getWitnessFileUrl } from './utils/did-identifier.js';
import { normalizeEd25519Multikey } from './utils/did-key.js';

/**
 * Normalizes caller-supplied update keys before an entry is hashed or signed.
 *
 * Accepts a bare Ed25519 multikey, a `did:key:` DID, or a `did:key:`
 * verification method id, and returns bare multikeys. Throws when an entry is
 * malformed or does not carry the Ed25519 multicodec header (0xed01).
 *
 * @param updateKeys {string[]} Caller-supplied update keys.
 * @returns {string[]} The same keys as bare multibase multikeys, in order.
 */
export function normalizeUpdateKeys(updateKeys: string[]): string[] {
  return updateKeys.map((key, index) => {
    try {
      return normalizeEd25519Multikey(key);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`Invalid updateKeys[${index}]: ${message}`);
    }
  });
}

/**
 * Applies {@link normalizeUpdateKeys} to an options object, leaving one that
 * carries no `updateKeys` untouched. Returns a copy, so the caller's options
 * object is not mutated.
 *
 * @param options {object} Options that may carry `updateKeys`.
 * @returns {object} The options, with any `updateKeys` normalized.
 */
export function withNormalizedUpdateKeys<T extends { updateKeys?: string[] }>(options: T): T {
  if (options.updateKeys === undefined) {
    return options;
  }
  return { ...options, updateKeys: normalizeUpdateKeys(options.updateKeys) };
}

export function parseAndValidateVersionId(versionId: string, expectedVersionNumber: number) {
  const firstDashIndex = versionId.indexOf('-');
  const lastDashIndex = versionId.lastIndexOf('-');

  if (firstDashIndex === -1 || firstDashIndex !== lastDashIndex) {
    throw new Error(`versionId '${versionId}' must contain exactly one '-' separator`);
  }

  const version = versionId.slice(0, firstDashIndex);
  const entryHash = versionId.slice(firstDashIndex + 1);

  if (!/^\d+$/.test(version)) {
    throw new Error(`versionId '${versionId}' must have a numeric version prefix`);
  }

  if (entryHash.length === 0) {
    throw new Error(`versionId '${versionId}' must have a non-empty hash component`);
  }

  const versionNumber = Number(version);
  if (versionNumber !== expectedVersionNumber) {
    throw new Error(`version '${version}' in log doesn't match expected '${expectedVersionNumber}'.`);
  }

  return { version, versionNumber, entryHash };
}

/**
 * Builds a log-entry `versionId` from its version number and entry hash --
 * the `<versionNumber>-<entryHash>` form `parseAndValidateVersionId` parses.
 */
export function buildVersionId(versionNumber: number, entryHash: string): string {
  return `${versionNumber}-${entryHash}`;
}

export function requireDidDocumentId(id: string | undefined): string {
  if (!id) {
    throw new Error('DID document id is missing');
  }

  return id;
}

type ProcessVersionsLike = { node?: string; bun?: string };

// Environment detection - treat React Native like a browser, but Bun as Node-like
const isNodeEnvironment =
  typeof process !== 'undefined' &&
  typeof window === 'undefined' &&
  !!(
    (process.versions as ProcessVersionsLike | undefined)?.node ||
    (process.versions as ProcessVersionsLike | undefined)?.bun
  );

const getFS = async (): Promise<typeof import('node:fs')> => {
  if (!isNodeEnvironment) {
    throw new Error('Filesystem access is not available in this environment (React Native or browser)');
  }
  // The magic comments keep browser bundlers from trying to resolve fs
  return import(/* @vite-ignore */ /* webpackIgnore: true */ 'node:fs');
};

/**
 * Parses a JSON Lines (`.jsonl`) DID log into an in-memory {@link DIDLog}.
 *
 * Tolerance rules: leading/trailing whitespace (including a trailing newline)
 * is trimmed before splitting, so a file ending in `\n` parses cleanly. Each
 * remaining line must be a complete JSON object; blank lines *between* entries
 * are not tolerated and will throw (`JSON.parse('')`). This is the inverse of
 * {@link logToJsonlString}.
 */
export const readLogFromString = (str: string): DIDLog => {
  return str
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
};

/**
 * Serializes a {@link DIDLog} to a JSON Lines (`.jsonl`) string: one JSON
 * object per line, newline-separated, with no trailing newline. Inverse of
 * {@link readLogFromString} (which tolerates a trailing newline on read). Every
 * self-hosting consumer needs this to publish the log as `did.jsonl`.
 */
export const logToJsonlString = (log: DIDLog): string => {
  return log.map((entry) => JSON.stringify(entry)).join('\n');
};

export const writeLogToDisk = async (path: string, log: DIDLog) => {
  const fs = await getFS();
  try {
    const dir = path.substring(0, path.lastIndexOf('/'));
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(path, `${logToJsonlString(log)}\n`);
  } catch (error) {
    console.error('Error writing log to disk:', error);
    throw error;
  }
};

/**
 * Fetches and parses a DID's log, `did.jsonl`.
 *
 * The request is bounded, because the URL comes from the DID. It has a
 * deadline, refuses redirects, and stops reading a body larger than the size
 * limit. The same bounds apply to a custom `fetchFn`, which receives
 * `redirect: 'error'` and an abort `signal`.
 *
 * A 404 or an empty log throws a `DIDResolutionError` with code `notFound`.
 * Any other HTTP status, and any transport failure, throws one with code
 * `internalError`.
 *
 * @param identifier {string} The DID whose log is fetched.
 * @param [fetchFn] {FetchLike} Fetch override. Defaults to the global `fetch`.
 * @param [bounds.timeoutMs] {number} Deadline in milliseconds. Defaults to 10
 *   seconds.
 * @param [bounds.maxBytes] {number} Body size limit in bytes. Defaults to 5
 *   MiB.
 * @returns {Promise<DIDLog>} The parsed log entries.
 */
export async function fetchLogFromIdentifier(
  identifier: string,
  fetchFn: FetchLike = fetch,
  bounds: { timeoutMs?: number; maxBytes?: number } = {}
): Promise<DIDLog> {
  const body = await fetchBounded(getFileUrl(identifier), fetchFn, bounds);
  if (body === undefined) {
    throw new DIDResolutionError('HTTP error! status: 404', { code: 'notFound' });
  }

  const text = body.trim();
  if (!text) {
    throw new DIDResolutionError(`DID log not found for ${identifier}`, { code: 'notFound' });
  }
  return readLogFromString(text);
}

/**
 * Whether `network` allows fetching the given file. `'none'` refuses both
 * files and `'log-only'` refuses the witness proofs file.
 */
export function networkPermits(network: ResolutionOptions['network'], file: 'log' | 'witness'): boolean {
  return network !== 'none' && (file === 'log' || network !== 'log-only');
}

/**
 * Loads a DID's log: the `resolveControlledDid` callback is consulted first,
 * and an `undefined` result falls back to fetching over HTTPS (through the
 * `fetch` override when one is given). With `network: 'none'` nothing is
 * fetched, and a log the callback does not supply throws a
 * `DIDResolutionError` with code `notFound`. An error thrown by the callback
 * is a retrieval failure: unless it is already a `DIDResolutionError`, it is
 * rethrown as one with code `internalError` and the original as `cause`.
 */
export async function loadDIDLog(
  did: string,
  { resolveControlledDid, fetch, network }: LogSourceOptions
): Promise<DIDLog> {
  let controlledLog: DIDLog | undefined;
  try {
    controlledLog = await resolveControlledDid?.(did);
  } catch (error) {
    throw toRetrievalError(error);
  }
  if (controlledLog) {
    return controlledLog;
  }
  if (!networkPermits(network, 'log')) {
    throw new DIDResolutionError(`DID log not found for ${did}: network is 'none', so it was not fetched`, {
      code: 'notFound',
    });
  }
  return fetchLogFromIdentifier(did, fetch);
}

/**
 * Fetches the `did-witness.json` file published beside a DID's log. A missing
 * file (404) means the DID has no witness proofs and returns an empty list.
 * Any other HTTP status, and any transport failure, throws a
 * `DIDResolutionError` with code `internalError`, so a transport problem is
 * not reported as an unmet witness threshold.
 *
 * The request is bounded, because the URL comes from the DID and so from
 * whoever wrote the log. It has a deadline, refuses redirects, and stops
 * reading a body larger than the size limit. The same bounds apply to a
 * custom `fetchFn`, which receives `redirect: 'error'` and an abort `signal`.
 *
 * @param did {string} The DID whose witness proof file is fetched.
 * @param [fetchFn] {FetchLike} Fetch override. Defaults to the global `fetch`.
 * @param [bounds.timeoutMs] {number} Deadline in milliseconds. Defaults to 10
 *   seconds.
 * @param [bounds.maxBytes] {number} Body size limit in bytes. Defaults to 5
 *   MiB.
 * @returns {Promise<WitnessProofFileEntry[]>} The published witness proofs.
 */
export async function fetchWitnessProofs(
  did: string,
  fetchFn: FetchLike = fetch,
  bounds: { timeoutMs?: number; maxBytes?: number } = {}
): Promise<WitnessProofFileEntry[]> {
  const url = getWitnessFileUrl(did);

  const text = await fetchBounded(url, fetchFn, bounds);
  if (text === undefined) {
    return [];
  }

  return parseWitnessProofFile(text, url);
}

/**
 * Parses the text of a witness proof file, which must be a JSON array.
 *
 * @param text {string} The file content.
 * @param source {string} Where the file came from, for the error message.
 * @returns {WitnessProofFileEntry[]} The witness proofs.
 */
export function parseWitnessProofFile(text: string, source: string): WitnessProofFileEntry[] {
  const body: unknown = JSON.parse(text);
  if (!Array.isArray(body)) {
    throw new Error(`Witness proof file at ${source} is not a JSON array`);
  }
  return body as WitnessProofFileEntry[];
}

/**
 * Loads a DID's witness proofs: supplied `witnessProofs` (even `[]`) are
 * always used, and otherwise the proof file is fetched. With `network: 'none'`
 * or `'log-only'` nothing is fetched, and proofs that were not supplied throw a
 * `DIDResolutionError` with code `notFound`. That is a retrieval failure,
 * like a failed fetch, and is not an unmet threshold.
 */
export async function loadWitnessProofs(
  did: string,
  { witnessProofs, fetch, network }: Pick<ResolutionOptions, 'witnessProofs' | 'fetch' | 'network'>
): Promise<WitnessProofFileEntry[]> {
  if (witnessProofs !== undefined) {
    return witnessProofs;
  }
  if (!networkPermits(network, 'witness')) {
    throw new DIDResolutionError(
      `Witness proofs not found for ${did}: network is '${network}', so they were not fetched; supply witnessProofs`,
      { code: 'notFound' }
    );
  }
  return fetchWitnessProofs(did, fetch);
}

// Re-exported from the leaf modules so existing importers of `./utils.js` are
// unaffected while `did-document.ts` (and other low layers) import them
// without an import cycle.
export type { ParsedDidWebvhIdentifier } from './utils/did-identifier.js';
export {
  getBaseUrl,
  getFileUrl,
  normalizeCreateDidAddress,
  normalizeUpdateDidAddress,
  parseCanonicalAddress,
  parseDidWebvhIdentifier,
  validateMethodSpecificPathSegments,
} from './utils/did-identifier.js';
export { parseDidKeyDid, parseDidKeyVerificationMethod } from './utils/did-key.js';
export { replaceValueInObject } from './utils/object.js';
