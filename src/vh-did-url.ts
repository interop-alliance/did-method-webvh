/**
 * did:vh DID URL parsing, shared by `dereference` and the did:vh driver.
 *
 * A did:vh DID URL is `did:vh:<scid>[?src=...][&versionId=...][#fragment]`.
 * The `src` parameter names where the DID's log is retrieved from. This
 * module is pure: it reads the URL and makes no request.
 */
import { DIDResolutionError } from '@interop/data-integrity-core';
import { type ParsedDidUrl, parseDidUrl } from './path-handler.js';
import type { VhResolutionOptions } from './vh.js';
import { deriveSrcReferences } from './vh-source.js';

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

function invalidUrl(detail: string): DIDResolutionError {
  return new DIDResolutionError(detail, { code: 'invalidDidUrl' });
}

function decodeSrc(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    throw new Error('The src parameter has a malformed percent-encoding.');
  }
}

/**
 * Splits a did:vh DID URL into its DID, version selectors, fragment and the
 * log references derived from its `src` parameter.
 *
 * `src` is percent-decoded once and validated, and `derived` holds the
 * `srcLog` / `srcWitness` references made from it by appending `/did.jsonl`
 * and `/did-witness.json`. `derived` is `undefined` when the URL carries no
 * `src`. `selectors` holds the version parameters the URL carries. The DID
 * itself is not validated here.
 *
 * Throws a `DIDResolutionError`. An invalid `src`, any other query parameter
 * and a malformed URL are `invalidDidUrl`. did:vh defines no DID URL path
 * handling, so a URL with a path is `notFound`.
 *
 * @param didUrl {string} The DID URL to parse.
 * @returns The parts of the URL.
 */
export function parseVhDidUrl(didUrl: string): {
  did: string;
  fragment?: string;
  selectors: Pick<ParsedDidUrl, 'versionId' | 'versionNumber' | 'versionTime'>;
  derived?: ReturnType<typeof deriveSrcReferences>;
} {
  if (typeof didUrl !== 'string') {
    throw invalidUrl('The DID URL must be a string.');
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
      throw invalidUrl(`'${name}' is a resolution option and must not be used as a DID URL query parameter.`);
    }
    if (name === 'src') {
      srcValues.push(pair.slice(name.length + 1));
    } else {
      otherPairs.push(pair);
    }
  }
  if (srcValues.length > 1) {
    throw invalidUrl('A DID URL may carry at most one src parameter.');
  }

  let parsed: ParsedDidUrl;
  let derived: ReturnType<typeof deriveSrcReferences> | undefined;
  try {
    // A query that held only `src` is dropped. An empty query (`did?`) is
    // kept, so the shared parser sees it.
    const keepQuery = query !== undefined && (otherPairs.length > 0 || srcValues.length === 0);
    const queryPart = keepQuery ? `?${otherPairs.join('&')}` : '';
    const fragmentPart = hashIndex === -1 ? '' : didUrl.slice(hashIndex);
    parsed = parseDidUrl(`${beforeQuery}${queryPart}${fragmentPart}`);
    if (srcValues.length === 1) {
      derived = deriveSrcReferences(decodeSrc(srcValues[0]));
    }
  } catch (error) {
    throw invalidUrl((error as Error).message);
  }
  const { did, path, fragment, ...selectors } = parsed;
  if (path !== '') {
    throw new DIDResolutionError(`did:vh defines no DID URL path handling, so ${didUrl} names no resource.`, {
      code: 'notFound',
    });
  }
  return { did, selectors, fragment, derived };
}

/**
 * Applies the parts of a parsed did:vh DID URL to resolution options.
 *
 * A version parameter in the URL replaces the version selectors among
 * `options`. The references derived from `src` are used only when `options`
 * names no log source of its own (`didLog` or `srcLog`), and the derived
 * `srcWitness` only when `options` names no witness file.
 *
 * @param parsed The `selectors` and `derived` parts from {@link parseVhDidUrl}.
 * @param options {VhResolutionOptions} The caller's resolution options.
 * @returns {VhResolutionOptions} The options to resolve the URL's DID with.
 */
export function applyVhDidUrl(
  { selectors, derived }: Pick<ReturnType<typeof parseVhDidUrl>, 'selectors' | 'derived'>,
  options: VhResolutionOptions
): VhResolutionOptions {
  const { versionId, versionNumber, versionTime, ...otherOptions } = options;
  const applied: VhResolutionOptions =
    Object.keys(selectors).length > 0 ? { ...otherOptions, ...selectors } : { ...options };
  if (derived && applied.didLog === undefined && applied.srcLog === undefined) {
    applied.srcLog = derived.srcLog;
    if (applied.didWitness === undefined && applied.srcWitness === undefined) {
      applied.srcWitness = derived.srcWitness;
    }
  }
  return applied;
}
