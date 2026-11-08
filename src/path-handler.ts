/**
 * DID URL path handling: the `PathHandler` service mechanism from the
 * did:webvh specification's "DID URL Path Handling" section (editors draft).
 *
 * A service is eligible to handle a DID URL path when its `type` includes
 * `PathHandler`. Of the eligible services, the one whose `path` is the
 * longest complete match from the beginning of the DID URL path is selected.
 * The matched `path` is removed from the DID URL path and the remainder is
 * appended to the service's `serviceEndpoint` to produce the location of the
 * resource. The specification's separate `PathService` type is not required:
 * every `PathHandler` service is handled this way.
 *
 * The implicit `#files` and `#whois` services the specification describes
 * are not considered: this fork does not inject them into resolved documents,
 * and this module reads only the services the document declares.
 *
 * This module is pure: it does no resolution and no network request.
 */
import { parseUtcIso8601VersionTime } from './utils/iso8601-datetime.js';

export const PATH_HANDLER_SERVICE_TYPE = 'PathHandler';

/** The DID URL parameters that select a version of the DID document. */
export const VERSION_SELECTOR_PARAMETERS = ['versionId', 'versionNumber', 'versionTime'] as const;
export type VersionSelectorParameter = (typeof VERSION_SELECTOR_PARAMETERS)[number];

/** A `did:webvh` DID URL split into its DID, path, version selector, and fragment. */
export interface ParsedDidUrl {
  /** Everything before the first `/`, `?`, or `#`. */
  did: string;
  /** The DID URL path including its leading `/`, or `''` when the URL has none. */
  path: string;
  versionId?: string;
  versionNumber?: number;
  versionTime?: Date;
  /** Everything after the `#`, or `undefined` when the URL has none or it is empty. */
  fragment?: string;
}

/** Percent-decodes one query component, naming the DID URL when the encoding is malformed. */
function decodeQueryComponent(component: string, didUrl: string): string {
  try {
    return decodeURIComponent(component);
  } catch {
    throw new Error(`Malformed percent-encoding in DID URL ${didUrl}`);
  }
}

/**
 * Splits a query string into its parameters, throwing on any name outside
 * `allowed`. Names are checked before values are decoded, so an unsupported
 * parameter is reported as such whatever its value. Values are
 * percent-decoded only, since a DID URL query is not form data: a literal `+`
 * (as in a `+00:00` offset) is kept.
 */
function parseQuery(
  query: string,
  didUrl: string,
  allowed: readonly VersionSelectorParameter[]
): Map<VersionSelectorParameter, string[]> {
  if (query === '') {
    throw new Error(`Empty query in DID URL ${didUrl}`);
  }
  const params = new Map<VersionSelectorParameter, string[]>();
  for (const pair of query.split('&')) {
    const equals = pair.indexOf('=');
    const name = decodeQueryComponent(equals === -1 ? pair : pair.slice(0, equals), didUrl);
    if (!(allowed as readonly string[]).includes(name)) {
      throw new Error(`Unsupported DID parameter '${name}' in DID URL ${didUrl}`);
    }
    const value = equals === -1 ? '' : decodeQueryComponent(pair.slice(equals + 1), didUrl);
    params.set(name as VersionSelectorParameter, [...(params.get(name as VersionSelectorParameter) ?? []), value]);
  }
  return params;
}

/**
 * Splits a DID URL of the form `<did>[/path][?versionId=...][#fragment]`.
 *
 * Only the version-selecting DID parameters (`versionId`, `versionNumber`,
 * `versionTime`) are supported, and `allowed` may narrow them further. Any
 * other query parameter throws, as does an empty query and a repeated,
 * valueless, or malformed parameter. `versionTime` must be a UTC ISO 8601
 * datetime, as the resolver requires. A selector is present on the result
 * only when the URL carries it. Which of the selectors may be combined is
 * left to resolution. The DID itself is not validated here.
 */
export function parseDidUrl(
  didUrl: string,
  allowed: readonly VersionSelectorParameter[] = VERSION_SELECTOR_PARAMETERS
): ParsedDidUrl {
  const hashIndex = didUrl.indexOf('#');
  const beforeFragment = hashIndex === -1 ? didUrl : didUrl.slice(0, hashIndex);
  const fragment = hashIndex === -1 ? '' : didUrl.slice(hashIndex + 1);

  const queryIndex = beforeFragment.indexOf('?');
  const beforeQuery = queryIndex === -1 ? beforeFragment : beforeFragment.slice(0, queryIndex);

  const slashIndex = beforeQuery.indexOf('/');
  const did = slashIndex === -1 ? beforeQuery : beforeQuery.slice(0, slashIndex);
  const path = slashIndex === -1 ? '' : beforeQuery.slice(slashIndex);

  const parsed: ParsedDidUrl = { did, path };
  if (fragment !== '') {
    parsed.fragment = fragment;
  }
  if (queryIndex === -1) {
    return parsed;
  }

  const params = parseQuery(beforeFragment.slice(queryIndex + 1), didUrl, allowed);
  const single = (name: VersionSelectorParameter): string | undefined => {
    const values = params.get(name) ?? [];
    if (values.length > 1) {
      throw new Error(`Repeated DID parameter '${name}' in DID URL ${didUrl}`);
    }
    if (values[0] === '') {
      throw new Error(`Empty DID parameter '${name}' in DID URL ${didUrl}`);
    }
    return values[0];
  };

  const versionId = single('versionId');
  if (versionId !== undefined) {
    parsed.versionId = versionId;
  }
  const versionNumber = single('versionNumber');
  if (versionNumber !== undefined) {
    if (!/^[1-9]\d*$/.test(versionNumber) || !Number.isSafeInteger(Number(versionNumber))) {
      throw new Error(`DID parameter 'versionNumber' must be a positive integer in DID URL ${didUrl}`);
    }
    parsed.versionNumber = Number(versionNumber);
  }
  const versionTime = single('versionTime');
  if (versionTime !== undefined) {
    parsed.versionTime = parseUtcIso8601VersionTime(versionTime, `DID parameter 'versionTime' in DID URL ${didUrl}`);
  }
  return parsed;
}

/**
 * The members of a service that path handling reads. Both this package's
 * `ServiceEndpoint` and the `service` entries of a resolution result's
 * `didDocument` satisfy it.
 */
export interface PathHandlerService {
  id?: string;
  type: string | string[];
  path?: unknown;
  serviceEndpoint?: unknown;
}

const serviceTypes = (service: PathHandlerService): string[] =>
  Array.isArray(service.type) ? service.type : [service.type];

export const isPathHandler = (service: PathHandlerService): boolean =>
  serviceTypes(service).includes(PATH_HANDLER_SERVICE_TYPE);

/**
 * The `path` of a service in the form matching uses: a trailing `/` is
 * dropped (`/images/` and `/images` name the same mount), except for the root
 * `/`. Returns `undefined` for a `path` that is not a string starting with
 * `/`; such a service is ignored rather than matching every DID URL path.
 */
function servicePath(service: PathHandlerService): string | undefined {
  const { path } = service;
  if (typeof path !== 'string' || !path.startsWith('/')) {
    return undefined;
  }
  return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

/**
 * Whether `servicePath` is a complete match from the beginning of `urlPath`:
 * equal to it, or a prefix of it ending at a segment boundary. `/images`
 * matches `/images` and `/images/logo.png` but not `/imagesx`; `/` matches
 * every path.
 */
function isCompletePrefix(servicePath: string, urlPath: string): boolean {
  return servicePath === '/' || urlPath === servicePath || urlPath.startsWith(`${servicePath}/`);
}

/** The `PathHandler` service selected for a DID URL path, and the path left after removing its `path`. */
export interface PathHandlerSelection {
  service: PathHandlerService;
  /** The rest of the DID URL path, with its leading `/`, or `''` when the service `path` matched it whole. */
  remainder: string;
}

/**
 * Selects the `PathHandler` service for `urlPath` from the services of `doc`.
 * The service whose `path` is the longest complete match wins; on a tie the
 * earlier service wins. A service whose `path` is not a string starting with
 * `/` is ignored. Returns `undefined` when no service matches.
 */
export function selectPathHandler(
  doc: { service?: PathHandlerService | PathHandlerService[] },
  urlPath: string
): PathHandlerSelection | undefined {
  let best: PathHandlerService | undefined;
  let bestPath = '';
  for (const service of [doc.service ?? []].flat()) {
    const matched = isPathHandler(service) ? servicePath(service) : undefined;
    if (
      matched !== undefined &&
      isCompletePrefix(matched, urlPath) &&
      (best === undefined || matched.length > bestPath.length)
    ) {
      best = service;
      bestPath = matched;
    }
  }
  if (best === undefined) {
    return undefined;
  }
  const remainder = bestPath === '/' ? urlPath : urlPath.slice(bestPath.length);
  return { service: best, remainder };
}

/**
 * The URL of the resource a `PathHandler` selection locates: the remainder of
 * the DID URL path appended to the service's `serviceEndpoint`, with exactly
 * one `/` between them when the remainder is not empty. Throws when the
 * service's `serviceEndpoint` is not a single string, or the endpoint carries
 * a query or fragment, which the appended path would corrupt.
 */
export function pathHandlerUrl({ service, remainder }: PathHandlerSelection): string {
  const endpoint = service.serviceEndpoint;
  if (typeof endpoint !== 'string') {
    throw new Error(`PathHandler ${service.id ?? '(no id)'} must have a single string serviceEndpoint`);
  }
  if (/[?#]/.test(endpoint)) {
    throw new Error(`PathHandler ${service.id ?? '(no id)'} serviceEndpoint must not carry a query or fragment`);
  }
  if (remainder === '') {
    return endpoint;
  }
  return `${endpoint.replace(/\/$/, '')}${remainder}`;
}
