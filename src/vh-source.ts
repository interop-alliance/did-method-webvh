/**
 * did:vh log sources: validation and retrieval of the `srcLog` and
 * `srcWitness` references, and the derivation of both from the `src` DID URL
 * parameter.
 *
 * A did:vh DID names no location, so the client says where the log is. A
 * reference names the file itself and is retrieved as given, with nothing
 * appended. `https` is always available. Loopback `http` and `file:` are
 * available only to a resolver its caller marks as local.
 */
import { DIDResolutionError } from '@interop/data-integrity-core';
import type { FetchLike } from './interfaces.js';
import { FETCH_MAX_BYTES, fetchBounded } from './utils/bounded-fetch.js';
import { hasControlCharacter, validateMethodSpecificPathSegments } from './utils/did-identifier.js';

const IPV4_PATTERN = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const LOOPBACK_IPV4_PATTERN = /^127(?:\.\d{1,3}){3}$/;
const SCHEME_PATTERN = /^([A-Za-z][A-Za-z0-9+.-]*):/;

/** A validated `srcLog` or `srcWitness` reference. */
export interface SourceReference {
  /** `other` is a scheme this library does not retrieve. */
  kind: 'web' | 'file' | 'other';
  /** The URL to retrieve, with a non-ASCII host converted to A-labels. */
  url: string;
}

const isIpHost = (hostname: string): boolean => hostname.startsWith('[') || IPV4_PATTERN.test(hostname);

const isLoopbackHost = (hostname: string): boolean =>
  hostname === 'localhost' || hostname === '[::1]' || LOOPBACK_IPV4_PATTERN.test(hostname);

/**
 * Refuses text that URL parsing would rewrite before the path is read. A URL
 * parser removes tab, CR and LF, trims the ends, and reads `\` as `/` for
 * `https`, `http` and `file`. The segment checks run on the reference as
 * written, so the written and the parsed form have to name the same path.
 * Throws a plain `Error`; the caller assigns the code.
 */
const assertParsesAsWritten = (value: string): void => {
  if (hasControlCharacter(value) || value.includes('\\') || value !== value.trim()) {
    throw new Error('must not contain a control character, a backslash, or whitespace at either end');
  }
};

/**
 * Checks the path segments of a reference as written, before URL parsing
 * removes dot segments. With `strict`, a segment that is empty, or begins or
 * ends with whitespace, is refused too. Throws a plain `Error`; the caller
 * assigns the code.
 */
const assertSafePathSegments = (segments: string[], strict: boolean): void => {
  if (strict) {
    validateMethodSpecificPathSegments(segments, 'path');
    return;
  }
  for (const segment of segments) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new Error('has a malformed percent-encoding in its path');
    }
    if (decoded === '.' || decoded === '..' || /[/\\\0]/.test(decoded)) {
      throw new Error(`has a path segment that is not allowed: '${segment}'`);
    }
  }
};

/**
 * Validates an `https` or `http` web location and returns the URL to
 * retrieve. Throws a plain `Error` describing the violation.
 *
 * @param value {string} The reference as given.
 * @param options.requirePath {boolean} Whether an empty path is refused.
 * @param options.allowQuery {boolean} Whether a query is allowed.
 * @param options.strictSegments {boolean} Whether a segment that is empty,
 *   or begins or ends with whitespace, is refused.
 */
const parseWebLocation = (
  value: string,
  { requirePath, allowQuery, strictSegments }: { requirePath: boolean; allowQuery: boolean; strictSegments: boolean }
): URL => {
  assertParsesAsWritten(value);
  if (value.includes('#')) {
    throw new Error('must not have a fragment');
  }
  if (!allowQuery && value.includes('?')) {
    throw new Error('must not have a query');
  }
  const parts = /^[A-Za-z]+:\/\/([^/?#]*)([^?#]*)/.exec(value);
  if (!parts || parts[1] === '') {
    throw new Error('must be an absolute URL with a host');
  }
  if (parts[1].includes('@')) {
    throw new Error('must not carry user information');
  }
  let path = parts[2];
  if (requirePath && path === '') {
    throw new Error('must have a path that names the file');
  }
  if (strictSegments && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  assertSafePathSegments(path.split('/').slice(1), strictSegments);

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('is not a valid URL');
  }
  if (url.protocol === 'https:' && isIpHost(url.hostname)) {
    throw new Error('must name its https host by domain name, and an IP address was given');
  }
  if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) {
    throw new Error('may use http only with a loopback host');
  }
  return url;
};

/**
 * Validates a `srcLog` or `srcWitness` value.
 *
 * An `https` URL needs a domain-name host, a path and no fragment. An `http`
 * URL is accepted only for a loopback host, and a `file:` URL only with an
 * absolute path and no query or fragment. Both of those also need `local`.
 * A violation throws a `DIDResolutionError` with code `invalidOptions`.
 *
 * A reference in any other scheme is returned with kind `other`, provided it
 * has no fragment. It is refused by {@link retrieveSource}, so a reference
 * that is never retrieved is not an error.
 *
 * @param value {unknown} The option value.
 * @param name {string} The option name, for the error message.
 * @param local {boolean} Whether the caller marked the resolver as local.
 * @returns {SourceReference} The validated reference.
 */
export function parseSourceReference(value: unknown, name: string, local: boolean): SourceReference {
  const invalid = (reason: string) => new DIDResolutionError(`${name} ${reason}`, { code: 'invalidOptions' });
  // The shared checks throw a plain `Error`; the option's code is assigned here.
  const check = <T>(run: () => T): T => {
    try {
      return run();
    } catch (error) {
      throw invalid((error as Error).message);
    }
  };
  if (typeof value !== 'string') {
    throw invalid('must be a string holding an absolute URL');
  }
  const scheme = SCHEME_PATTERN.exec(value)?.[1].toLowerCase();
  if (scheme === undefined) {
    throw invalid('must be an absolute URL');
  }

  if (scheme === 'https' || scheme === 'http') {
    const url = check(() => parseWebLocation(value, { requirePath: true, allowQuery: true, strictSegments: false }));
    if (url.protocol === 'http:' && !local) {
      throw invalid('is a loopback reference, which only a resolver marked as local may retrieve');
    }
    return { kind: 'web', url: url.href };
  }

  if (scheme === 'file') {
    if (!local) {
      throw invalid('is a local file reference, which only a resolver marked as local may read');
    }
    if (value.includes('?') || value.includes('#')) {
      throw invalid('must not have a query or fragment');
    }
    const parts = /^file:\/\/([^/]*)(\/.*)$/i.exec(value);
    check(() => assertParsesAsWritten(value));
    if (!parts || (parts[1] !== '' && parts[1].toLowerCase() !== 'localhost')) {
      throw invalid('must be a file: URL with an absolute path and an empty or localhost host');
    }
    const { 2: path } = parts;
    check(() => assertSafePathSegments(path.split('/').slice(1), false));
    return { kind: 'file', url: `file://${path}` };
  }

  if (value.includes('#')) {
    throw invalid('must not have a fragment');
  }
  return { kind: 'other', url: value };
}

const readLocalFile = async (url: string): Promise<string | undefined> => {
  let fs: typeof import('node:fs/promises');
  let fileURLToPath: typeof import('node:url')['fileURLToPath'];
  try {
    // The magic comments keep browser bundlers from trying to resolve these.
    fs = await import(/* @vite-ignore */ /* webpackIgnore: true */ 'node:fs/promises');
    ({ fileURLToPath } = await import(/* @vite-ignore */ /* webpackIgnore: true */ 'node:url'));
  } catch {
    throw new DIDResolutionError('Local file references are not available in this environment', {
      code: 'featureNotSupported',
    });
  }
  const path = fileURLToPath(url);
  let info: Awaited<ReturnType<typeof fs.stat>>;
  try {
    info = await fs.stat(path);
  } catch {
    return undefined;
  }
  // A device or FIFO reports no size and may not reach end of file.
  if (!info.isFile()) {
    return undefined;
  }
  // The limit on a fetched body applies to a local file too.
  if (info.size > FETCH_MAX_BYTES) {
    throw new DIDResolutionError(`The local file exceeds the ${FETCH_MAX_BYTES} byte limit`, {
      code: 'internalError',
    });
  }
  try {
    return await fs.readFile(path, 'utf8');
  } catch {
    return undefined;
  }
};

/**
 * Retrieves a validated reference. A web location goes through
 * `fetchBounded` (deadline, body size limit, redirects refused). A reference
 * of kind `other` throws a `DIDResolutionError` with code
 * `featureNotSupported`.
 *
 * @param reference {SourceReference} The reference to retrieve.
 * @param [fetchFn] {FetchLike} Fetch override. Defaults to the global `fetch`.
 * @returns {Promise<string | undefined>} The content, or `undefined` when the
 *   file does not exist (a 404, or a local path that cannot be read or is
 *   not a regular file).
 */
export async function retrieveSource(
  reference: SourceReference,
  fetchFn: FetchLike = fetch
): Promise<string | undefined> {
  if (reference.kind === 'other') {
    const scheme = SCHEME_PATTERN.exec(reference.url)?.[1].toLowerCase();
    throw new DIDResolutionError(`The '${scheme}' scheme of ${reference.url} is not one this resolver retrieves`, {
      code: 'featureNotSupported',
    });
  }
  return reference.kind === 'file' ? readLocalFile(reference.url) : fetchBounded(reference.url, fetchFn);
}

/**
 * Validates the value of a did:vh `src` DID URL parameter, already
 * percent-decoded once, and derives the two references from it.
 *
 * The value must be an absolute URL with no query or fragment, using `https`
 * or another scheme with hierarchical paths. `file:` and `http` are refused.
 * An `https` value needs a domain-name host; its path may be empty. One
 * trailing `/` is removed, then `/did.jsonl` and `/did-witness.json` are
 * appended. A violation throws a `DIDResolutionError` with code
 * `invalidDidUrl`.
 *
 * @param src {string} The decoded `src` value.
 * @returns {{ srcLog: string, srcWitness: string }} The derived references.
 */
export function deriveSrcReferences(src: string): { srcLog: string; srcWitness: string } {
  const invalid = (reason: string) => new DIDResolutionError(`The src parameter ${reason}`, { code: 'invalidDidUrl' });
  const scheme = SCHEME_PATTERN.exec(src)?.[1].toLowerCase();
  if (scheme === undefined) {
    throw invalid('must be an absolute URL');
  }
  if (scheme === 'file' || scheme === 'http') {
    throw invalid(`must not use the '${scheme}' scheme`);
  }
  if (src.includes('?') || src.includes('#')) {
    throw invalid('must not have a query or fragment');
  }
  if (scheme === 'https') {
    try {
      parseWebLocation(src, { requirePath: false, allowQuery: false, strictSegments: true });
    } catch (error) {
      throw invalid((error as Error).message);
    }
  } else if (!src.slice(scheme.length + 1).startsWith('//')) {
    throw invalid('must use a scheme with hierarchical paths');
  }
  const base = src.endsWith('/') ? src.slice(0, -1) : src;
  return { srcLog: `${base}/did.jsonl`, srcWitness: `${base}/did-witness.json` };
}
