/**
 * The did:vh method API, exported as the `/vh` subpath.
 *
 * did:vh is did:webvh with the location removed from the DID: a did:vh DID is
 * `did:vh:<scid>`. The log format, SCID and entry-hash algorithms, key
 * authorization, pre-rotation and witness rules are shared with did:webvh,
 * and this module runs the same log code under the did:vh method profile.
 * The client sources the log and passes it to the resolver, directly
 * (`didLog`) or by reference (`srcLog`).
 *
 * The did:vh specification is an Editors Draft. Treat this API as unstable
 * until the specification reaches Draft status.
 */
import { DIDResolutionError, type IDIDResolutionResult } from '@interop/data-integrity-core';
import { PLACEHOLDER } from './constants.js';
import type {
  CreateDIDInterface,
  CreateDIDResult,
  DeactivateDIDInterface,
  DIDLog,
  FetchLike,
  ResolutionOptions,
  ResolveVerificationMethod,
  UpdateDIDInterface,
  UpdateDIDResult,
  Verifier,
  WitnessProofFileEntry,
} from './interfaces.js';
import * as v1 from './method_versions/method.v1.0.js';
import { VH_PROFILE } from './method_versions/profile.js';
import { parseDidUrl } from './path-handler.js';
import {
  mapErrorToVhCode,
  toErrorResult,
  toResolutionResult,
  validateSingleVersionSelector,
} from './resolver-result.js';
import { parseDidVhIdentifier } from './utils/did-vh-identifier.js';
import { logToJsonlString, networkPermits, parseWitnessProofFile, readLogFromString } from './utils.js';
import { defaultWebvhLogVerifier } from './verifier.js';
import { deriveSrcReferences, parseSourceReference, retrieveSource, type SourceReference } from './vh-source.js';

export { VH_METHOD_PROTOCOL_V1_0 } from './constants.js';
/** Codes a did:vh resolution reports on `didResolutionMetadata.error`. */
export type { ResolutionErrorCode as VhResolutionError } from './resolver-result.js';
export { parseDidVhIdentifier } from './utils/did-vh-identifier.js';
export { deriveSrcReferences } from './vh-source.js';

/** The resolution options that are never DID URL query parameters. */
const RESOLUTION_ONLY_OPTIONS = [
  'didLog',
  'didWitness',
  'srcLog',
  'srcWitness',
  'checkWatchers',
  'extraWatchers',
  'minCopies',
  'includeDidLog',
];

/** Options for did:vh {@link resolveDID} and {@link dereference}. */
export interface VhResolutionOptions {
  /** The DID log passed directly, as JSON Lines text or as parsed entries. */
  didLog?: string | DIDLog;
  /** The witness proofs file passed directly, as its parsed JSON array. */
  didWitness?: WitnessProofFileEntry[];
  /** An absolute URL naming the log file itself. Nothing is appended to it. */
  srcLog?: string;
  /**
   * An absolute URL naming the witness proofs file itself. It is retrieved
   * only when the log requires witnesses.
   */
  srcWitness?: string;
  versionId?: string;
  versionTime?: Date;
  versionNumber?: number;
  /**
   * Return the verified log (as JSON Lines text) and, when witnesses are
   * required, the witness proofs file as `didLog` / `didWitness` in the
   * resolution metadata. Neither is returned when resolution fails.
   */
  includeDidLog?: boolean;
  /** Copy comparison is not implemented; any value but `0` returns `featureNotSupported`. */
  checkWatchers?: number | 'all';
  /** Copy comparison is not implemented; a non-empty list returns `featureNotSupported`. */
  extraWatchers?: string[];
  /** Copy comparison is not implemented; any value but `1` returns `featureNotSupported`. */
  minCopies?: number;
  /**
   * Marks the resolver as local: used on the same system as its client, and
   * not accepting requests from other systems. Only a local resolver may
   * retrieve a loopback `http` reference or read a `file:` reference. Any
   * other resolver returns `invalidOptions` for them.
   */
  local?: boolean;
  verifier?: Verifier;
  /** See {@link ResolutionOptions.resolveVM}. */
  resolveVM?: ResolveVerificationMethod;
  /** Fetch override for `srcLog` and `srcWitness`; defaults to the global `fetch`. */
  fetch?: FetchLike;
  /**
   * Which network requests the call may make. With `'none'` neither
   * reference is fetched. With `'log-only'` the log is fetched and the
   * witness proofs file is not. A `file:` reference is not a network request.
   */
  network?: ResolutionOptions['network'];
}

/**
 * Renders a thrown failure as a result. A `DIDResolutionError` carries its
 * own code; anything else is a verification failure, `invalidDid`.
 */
function thrownToResult(error: unknown): IDIDResolutionResult {
  return toErrorResult(mapErrorToVhCode(error), error instanceof Error ? error.message : String(error));
}

function isPositiveInteger(value: unknown): boolean {
  return Number.isSafeInteger(value) && (value as number) >= 1;
}

function isHttpsUrl(value: unknown): boolean {
  try {
    return typeof value === 'string' && new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Checks the shape and combination of the resolution options. Returns the
 * error result for the first violation, or `null`. A malformed option is
 * `invalidOptions`; a well-formed copy-comparison option is
 * `featureNotSupported`, since copy comparison is not implemented.
 */
function validateOptions(options: VhResolutionOptions): IDIDResolutionResult | null {
  const invalid = (detail: string) => toErrorResult('invalidOptions', detail);
  const { didLog, didWitness, srcLog, srcWitness, versionId, versionTime, versionNumber } = options;

  if ((didLog === undefined) === (srcLog === undefined)) {
    return invalid('Exactly one of didLog and srcLog must be given.');
  }
  if (didLog !== undefined && typeof didLog !== 'string' && !Array.isArray(didLog)) {
    return invalid('didLog must be the DID log as JSON Lines text or as an array of entries.');
  }
  if (didWitness !== undefined && srcWitness !== undefined) {
    return invalid('At most one of didWitness and srcWitness may be given.');
  }
  if (didWitness !== undefined && !Array.isArray(didWitness)) {
    return invalid('didWitness must be the witness proofs file as a JSON array.');
  }

  const selectorError = validateSingleVersionSelector(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, selectorError.problemType);
  }
  if (versionId !== undefined && typeof versionId !== 'string') {
    return invalid('versionId must be a string.');
  }
  if (versionTime !== undefined && !(versionTime instanceof Date && !Number.isNaN(versionTime.getTime()))) {
    return invalid('versionTime must be a valid Date.');
  }
  if (versionNumber !== undefined && !isPositiveInteger(versionNumber)) {
    return invalid('versionNumber must be a positive integer.');
  }
  if (options.includeDidLog !== undefined && typeof options.includeDidLog !== 'boolean') {
    return invalid('includeDidLog must be a boolean.');
  }

  const { checkWatchers = 0, extraWatchers = [], minCopies = 1 } = options;
  if (checkWatchers !== 'all' && !(Number.isSafeInteger(checkWatchers) && checkWatchers >= 0)) {
    return invalid("checkWatchers must be a non-negative integer or 'all'.");
  }
  if (!Array.isArray(extraWatchers) || !extraWatchers.every(isHttpsUrl)) {
    return invalid('extraWatchers must be a list of https URLs.');
  }
  if (!isPositiveInteger(minCopies)) {
    return invalid('minCopies must be a positive integer.');
  }
  if (checkWatchers !== 0 || extraWatchers.length > 0 || minCopies > 1) {
    return toErrorResult(
      'featureNotSupported',
      'Copy comparison (checkWatchers, extraWatchers, minCopies) is not supported by this resolver.'
    );
  }
  return null;
}

function decodeSrc(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    throw new Error('The src parameter has a malformed percent-encoding.');
  }
}

function notFound(message: string): DIDResolutionError {
  return new DIDResolutionError(message, { code: 'notFound' });
}

/** Whether `network` refuses the retrieval of `reference`. A local file is not a network request. */
function networkRefuses(reference: SourceReference, network: VhResolutionOptions['network'], file: 'log' | 'witness') {
  return reference.kind === 'web' && !networkPermits(network, file);
}

async function loadLog(options: VhResolutionOptions, reference: SourceReference | undefined): Promise<DIDLog> {
  if (Array.isArray(options.didLog)) {
    return options.didLog;
  }
  let text = options.didLog;
  if (reference) {
    if (networkRefuses(reference, options.network, 'log')) {
      throw notFound(`DID log not found: network is '${options.network}', so it was not fetched`);
    }
    text = await retrieveSource(reference, options.fetch);
    if (text === undefined || text.trim() === '') {
      throw notFound(`DID log not found at ${reference.url}`);
    }
  }
  try {
    return readLogFromString(text ?? '');
  } catch {
    throw new Error('The DID log is not valid JSON Lines');
  }
}

async function loadWitnessFile(
  options: VhResolutionOptions,
  reference: SourceReference | undefined
): Promise<WitnessProofFileEntry[]> {
  if (options.didWitness) {
    return options.didWitness;
  }
  // With no witness file, resolution proceeds as if the file held no proofs.
  if (!reference) {
    return [];
  }
  if (networkRefuses(reference, options.network, 'witness')) {
    throw notFound(
      `Witness proofs file not found: network is '${options.network}', so it was not fetched; supply didWitness`
    );
  }
  const text = await retrieveSource(reference, options.fetch);
  if (text === undefined) {
    return [];
  }
  return parseWitnessProofFile(text, reference.url);
}

/**
 * Resolves a did:vh DID from a log the caller supplies.
 *
 * Exactly one of `didLog` (the log itself) and `srcLog` (a URL naming the
 * log file) is required. With `didLog` and `didWitness` no network request
 * is made. `srcLog` and `srcWitness` are retrieved as given, with nothing
 * appended; `srcWitness` only when the log requires witnesses. A missing
 * witness file is read as one holding no proofs. A reference in a scheme
 * this resolver does not retrieve returns `featureNotSupported` when it is
 * retrieved, so an unneeded `srcWitness` in such a scheme is not an error.
 *
 * Returns a DID Resolution result envelope and does not throw. `ttl` and the
 * witness `threshold` are integers in the document metadata. `ttl`,
 * `witness`, `watchers` and `updated` are those of the last valid entry,
 * also when a version selector picks an earlier one.
 *
 * An entry whose witness threshold is not met fails verification, like one
 * with a bad proof. The valid entries are those before the first entry that
 * fails. With no version selector the result is the last valid entry, with
 * an `invalid-entries` item in `didResolutionMetadata.warnings`. A selector
 * that picks a valid entry succeeds, and one that picks a later entry
 * returns `invalidDid`. A retrieval or internal failure during verification
 * is returned under its own code and is not read as an entry failing.
 *
 * A log declaring a newer did:vh `method` version returns
 * `featureNotSupported` unless a selector picks an entry before it. The
 * copy-comparison options return `featureNotSupported` too.
 *
 * @param did {string} The DID to resolve, `did:vh:<scid>`.
 * @param options {VhResolutionOptions} The log source and resolver settings.
 * @returns {Promise<IDIDResolutionResult>} The resolution result envelope.
 */
export async function resolveDID(did: string, options: VhResolutionOptions): Promise<IDIDResolutionResult> {
  let scid: string;
  try {
    scid = parseDidVhIdentifier(did, 'did');
  } catch (error) {
    return toErrorResult('invalidDid', (error as Error).message);
  }
  const optionsError = validateOptions(options ?? {});
  if (optionsError) {
    return optionsError;
  }

  try {
    const local = options.local === true;
    const logReference =
      options.srcLog === undefined ? undefined : parseSourceReference(options.srcLog, 'srcLog', local);
    const witnessReference =
      options.srcWitness === undefined ? undefined : parseSourceReference(options.srcWitness, 'srcWitness', local);

    const log = await loadLog(options, logReference);
    let witnessFile: WitnessProofFileEntry[] | undefined;

    const core = await v1.traverseDIDLog(log, {
      profile: VH_PROFILE,
      returnLastValidEntry: true,
      verifier: options.verifier ?? defaultWebvhLogVerifier,
      ...(options.resolveVM ? { resolveVM: options.resolveVM } : {}),
      fetch: options.fetch,
      network: options.network,
      versionId: options.versionId,
      versionTime: options.versionTime,
      versionNumber: options.versionNumber,
      scid,
      requestedDid: did,
      loadWitnessProofs: async () => {
        witnessFile = await loadWitnessFile(options, witnessReference);
        return witnessFile;
      },
    });

    const result = toResolutionResult(core);
    // `ttl`, `witness`, `watchers` and `updated` are the values active at the
    // last valid entry, whichever version was selected.
    const { lastValidMeta, validEntryCount, invalidEntryError } = core;
    const { ttl: _ttl, witness: _witness, watchers: _watchers, ...documentMetadata } = result.didDocumentMetadata;
    result.didDocumentMetadata = {
      ...documentMetadata,
      ...(lastValidMeta.ttl === undefined ? {} : { ttl: lastValidMeta.ttl }),
      ...(lastValidMeta.witness ? { witness: lastValidMeta.witness } : {}),
      ...(lastValidMeta.watchers ? { watchers: lastValidMeta.watchers } : {}),
      updated: lastValidMeta.updated,
    };
    if (core.meta.error) {
      return result;
    }

    if (invalidEntryError !== undefined) {
      const reason = invalidEntryError instanceof Error ? invalidEntryError.message : String(invalidEntryError);
      result.didResolutionMetadata.warnings = [
        {
          code: 'invalid-entries',
          message: `Entries after version ${validEntryCount} failed verification: ${reason}`,
        },
      ];
    }
    if (options.includeDidLog) {
      result.didResolutionMetadata.didLog = logToJsonlString(log.slice(0, validEntryCount));
      if (witnessFile !== undefined) {
        result.didResolutionMetadata.didWitness = witnessFile;
      }
    }
    return result;
  } catch (error) {
    return thrownToResult(error);
  }
}

/**
 * Dereferences a did:vh DID URL to the resolution result of its DID.
 *
 * The URL may carry the `src` parameter and one of `versionId`,
 * `versionTime` and `versionNumber`. A version parameter in the URL replaces
 * the version selectors among `options`. `src` is percent-decoded once and
 * validated, and `srcLog` / `srcWitness` are derived from it by appending
 * `/did.jsonl` and `/did-witness.json`. The derived references are used only
 * when `options` names no log source of its own (`didLog` or `srcLog`), and
 * the derived `srcWitness` only when `options` names no witness file.
 *
 * An invalid `src`, any other query parameter, and a malformed URL return
 * `invalidDidUrl`. did:vh defines no DID URL path handling, so a URL with a
 * path returns `notFound`. A fragment is not applied: the result is that of
 * the DID document, and the caller selects the member the fragment names.
 *
 * @param didUrl {string} The DID URL to dereference.
 * @param [options] {VhResolutionOptions} Resolver settings, as for {@link resolveDID}.
 * @returns {Promise<IDIDResolutionResult>} The resolution result envelope.
 */
export async function dereference(didUrl: string, options: VhResolutionOptions = {}): Promise<IDIDResolutionResult> {
  const invalidUrl = (detail: string) => toErrorResult('invalidDidUrl', detail);
  if (typeof didUrl !== 'string') {
    return invalidUrl('The DID URL must be a string.');
  }
  const hashIndex = didUrl.indexOf('#');
  const beforeFragment = hashIndex === -1 ? didUrl : didUrl.slice(0, hashIndex);
  const queryIndex = beforeFragment.indexOf('?');
  const query = queryIndex === -1 ? undefined : beforeFragment.slice(queryIndex + 1);
  const beforeQuery = queryIndex === -1 ? beforeFragment : beforeFragment.slice(0, queryIndex);

  // `src` is taken out of the query here; the shared DID URL parser reads
  // the version parameters and refuses everything else.
  const srcValues: string[] = [];
  const otherPairs: string[] = [];
  for (const pair of query?.split('&') ?? []) {
    const name = pair.split('=', 1)[0];
    if (RESOLUTION_ONLY_OPTIONS.includes(name)) {
      return invalidUrl(`'${name}' is a resolution option and must not be used as a DID URL query parameter.`);
    }
    if (name === 'src') {
      srcValues.push(pair.slice(name.length + 1));
    } else {
      otherPairs.push(pair);
    }
  }
  if (srcValues.length > 1) {
    return invalidUrl('A DID URL may carry at most one src parameter.');
  }

  let parsed: ReturnType<typeof parseDidUrl>;
  let derived: ReturnType<typeof deriveSrcReferences> | undefined;
  try {
    const hasQuery = query !== undefined && (otherPairs.length > 0 || srcValues.length === 0);
    parsed = parseDidUrl(`${beforeQuery}${hasQuery ? `?${otherPairs.join('&')}` : ''}`);
    if (srcValues.length === 1) {
      derived = deriveSrcReferences(decodeSrc(srcValues[0]));
    }
  } catch (error) {
    return invalidUrl((error as Error).message);
  }
  const { did, path, fragment: _fragment, ...selectors } = parsed;
  if (path !== '') {
    return toErrorResult('notFound', `did:vh defines no DID URL path handling, so ${didUrl} names no resource.`);
  }

  const { versionId, versionNumber, versionTime, ...otherOptions } = options;
  const resolutionOptions: VhResolutionOptions =
    Object.keys(selectors).length > 0 ? { ...otherOptions, ...selectors } : { ...options };
  if (derived && resolutionOptions.didLog === undefined && resolutionOptions.srcLog === undefined) {
    resolutionOptions.srcLog = derived.srcLog;
    if (resolutionOptions.didWitness === undefined && resolutionOptions.srcWitness === undefined) {
      resolutionOptions.srcWitness = derived.srcWitness;
    }
  }
  return resolveDID(did, resolutionOptions);
}

/**
 * Creates a new did:vh DID and its first log entry. The DID is
 * `did:vh:<scid>`, and the entry declares `method: did:vh:1.0`.
 *
 * The options are those of the did:webvh `createDID` without `address`,
 * `paths`, `portable` and `alsoKnownAsWeb`, which have no meaning without a
 * location and throw when passed. An authored `didDocument` names itself
 * `did:vh:{SCID}` (or `{DID}`).
 *
 * @param options DID creation options.
 * @returns The created DID, its document, metadata and log.
 */
export async function createDID(
  options: Omit<CreateDIDInterface, (typeof v1.LOCATION_OPTIONS)[number]>
): Promise<CreateDIDResult> {
  return v1.createDIDForController(
    { ...options, verifier: options.verifier ?? defaultWebvhLogVerifier },
    `did:vh:${PLACEHOLDER}`,
    VH_PROFILE
  );
}

/**
 * Appends an update entry to a did:vh log. The options are those of the
 * did:webvh `updateDID` without `address`, `paths`, `portable` and
 * `alsoKnownAsWeb`, which throw when passed.
 *
 * Two rules differ from did:webvh. While pre-rotation is active,
 * `nextKeyHashes` must be passed with every update (`[]` ends pre-rotation).
 * And an update that sets `updateKeys` to `[]` ends the log.
 *
 * Nothing is fetched for the prior log's witness proofs: pass them as
 * `witnessProofs`, and an omitted list is read as no proofs.
 *
 * @param options DID update options.
 * @returns The DID, its updated document, metadata and log.
 */
export async function updateDID(
  options: Omit<UpdateDIDInterface, (typeof v1.LOCATION_OPTIONS)[number]>
): Promise<UpdateDIDResult> {
  return v1.updateDID({ ...options, verifier: options.verifier ?? defaultWebvhLogVerifier }, VH_PROFILE);
}

/**
 * Deactivates a did:vh DID by appending an entry that sets
 * `deactivated: true`. No entry may follow it. The options and the
 * pre-rotation refusal are those of the did:webvh `deactivateDID`. An
 * omitted `witnessProofs` list is read as no proofs; nothing is fetched.
 *
 * @param options DID deactivation options.
 * @returns The deactivated DID result and updated log.
 */
export async function deactivateDID(options: DeactivateDIDInterface) {
  return v1.deactivateDID({ ...options, verifier: options.verifier ?? defaultWebvhLogVerifier }, VH_PROFILE);
}

/**
 * Resolves a did:vh log held in memory to this package's core result shape
 * (`{ did, doc, meta }`), for tooling that acts on the log. It throws on a
 * verification failure. An omitted `witnessProofs` list is read as no
 * proofs; nothing is fetched for it. {@link resolveDID} is the entry point
 * that returns a DID Resolution result.
 *
 * @param log In-memory DID log entries.
 * @param [options] Resolver settings.
 * @returns The resolved DID, document and metadata.
 */
export async function resolveDIDFromLog(log: DIDLog, options: ResolutionOptions = {}) {
  return v1.resolveDIDFromLog(log, {
    ...options,
    verifier: options.verifier ?? defaultWebvhLogVerifier,
    profile: VH_PROFILE,
  });
}
