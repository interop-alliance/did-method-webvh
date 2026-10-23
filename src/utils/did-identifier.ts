/**
 * did:webvh identifier grammar and resolution-URL derivation.
 *
 * Leaf module (imports only constants) so higher layers -- `did-document.ts`,
 * the method implementations, and `utils.ts` -- can all share one parser
 * without import cycles.
 */
import { METHOD, PLACEHOLDER as SCID_PLACEHOLDER } from '../constants.js';

const DID_PREFIX = `did:${METHOD}:`;
const DEFAULT_CONTEXT = 'did:webvh identifier';
/** DID Core `idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded`. */
const DID_PATH_SEGMENT_PATTERN = /^(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$/;
/** A percent-encoded byte below 0x80, i.e. an ASCII character that did not need encoding. */
const ENCODED_ASCII_PATTERN = /%[0-7][0-9A-Fa-f]/;
/** Spec ABNF: `scid = 46(base58btc-char)`. */
const SCID_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{46}$/;
// SCID-shaped text that stands in for the SCID token while a host carrying the
// token is checked against DNS label and name lengths. It is used for the
// check only; the host handed back keeps the token verbatim.
const SCID_STAND_IN = '1'.repeat(46);
/** The port separator of a DID domain component, in either hex case. Emitted as `%3A`. */
const ENCODED_PORT_SEPARATOR = /%3a/i;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
/** WHATWG URL treats a host whose last label is decimal or `0x` hex as an IPv4 literal. */
const IPV4_LAST_LABEL_PATTERN = /^(?:\d+|0x[0-9a-f]*)$/i;

// Canonical address parser for strict parity with didwebvh-rs
export interface ParsedAddress {
  /** Lowercase A-label host. A SCID token (`{SCID}` or the SCID) is kept verbatim. */
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
  paths?: string[];
}

export interface ParsedDidWebvhIdentifier {
  scid: string;
  didDomainComponent: string;
  paths?: string[];
  locationKey: string;
}

/**
 * This fork's deliberate divergence from upstream: `http` is allowed for
 * `localhost` only (local development and testing); every other host is
 * HTTPS-only. This predicate is the single owner of that exception.
 */
const isLocalhost = (host: string): boolean => host === 'localhost';

/** Scheme for a resolution URL: `http` for localhost, `https` everywhere else. */
const schemeForHost = (host: string): 'http' | 'https' => (isLocalhost(host) ? 'http' : 'https');

/**
 * IPv6 literals (with or without brackets) and IPv4 literals in every form
 * WHATWG URL accepts (`127.0.0.1`, `127.1`, `0x7f.1`, `0177.0.0.1`), so a host
 * that fetch would resolve to an address is rejected as one.
 */
function isIPAddress(host: string): boolean {
  if (host.includes(':') || /^\[.*\]$/.test(host)) return true;
  const labels = host.replace(/\.$/, '').split('.');
  return IPV4_LAST_LABEL_PATTERN.test(labels[labels.length - 1]);
}

function isDoubleEncoded(value: string): boolean {
  // Detect %25 (which is percent-encoded %)
  return value.includes('%25');
}

function hasFragmentOrQuery(value: string): boolean {
  return value.includes('#') || value.includes('?');
}

const hasNonAscii = (value: string): boolean => /[\u0080-\u{10FFFF}]/u.test(value);

/** C0 controls and DEL. */
const hasControlCharacter = (value: string): boolean =>
  [...value].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || code === 127;
  });

const hasInvalidHostCharacter = (value: string): boolean =>
  hasControlCharacter(value) || [...value].some((char) => '%/#?@:\\'.includes(char) || /\s/.test(char));

// `\p{Surrogate}` under the `u` flag matches only unpaired surrogates
// (String.prototype.isWellFormed is ES2024 and not available on every runtime).
const hasUnpairedSurrogate = (value: string): boolean => /\p{Surrogate}/u.test(value);

/** Splits `value` around occurrences of the SCID token; a single part when there is no token. */
const splitAroundToken = (value: string, token?: string): string[] => (token ? value.split(token) : [value]);

/** Replaces the SCID token with SCID-shaped text, for length and syntax checks only. */
const withStandIn = (value: string, token?: string): string => (token ? value.replaceAll(token, SCID_STAND_IN) : value);

const UNICODE_TOKEN_LABEL_ERROR = 'Unicode and {SCID} cannot share a domain label';

/**
 * Whether `host` (with the SCID token stood in for) is at most 253 characters,
 * has at least two labels, and every label satisfies `isValidLabel`.
 */
function hasFqdnShape(host: string, token: string | undefined, isValidLabel: (label: string) => boolean): boolean {
  const checked = withStandIn(host, token);
  const labels = checked.split('.');
  return checked.length <= 253 && labels.length >= 2 && labels.every(isValidLabel);
}

let urlSupportsIdna: boolean | undefined;

/**
 * Converts a Unicode host to its A-label form using the runtime's WHATWG URL
 * implementation. Runtimes whose URL cannot apply IDNA (e.g. bare React Native)
 * are detected once and rejected rather than producing a wrong host. The
 * scheme has no effect on hostname parsing, so `https` is used throughout.
 */
function urlToASCII(host: string): string {
  try {
    urlSupportsIdna ??=
      new URL('https://faß.de').hostname === 'xn--fa-hia.de' &&
      new URL('https://BÜCHER.example').hostname === 'xn--bcher-kva.example';
  } catch {
    urlSupportsIdna = false;
  }
  if (!urlSupportsIdna) {
    throw new Error("This runtime's URL implementation does not support IDNA; use an A-label (xn--) domain instead");
  }
  try {
    return new URL(`https://${host}`).hostname;
  } catch {
    throw new Error('Host must be a valid fully qualified domain');
  }
}

/**
 * Maps one decoded host label to its lowercase A-label. A label carrying the
 * SCID token has to be ASCII; the token is kept verbatim and the text around
 * it is lowercased.
 */
function asciiLabel(label: string, token?: string): string {
  if (token && label.includes(token)) {
    if (hasNonAscii(label)) {
      throw new Error(UNICODE_TOKEN_LABEL_ERROR);
    }
    return label
      .split(token)
      .map((part) => part.toLowerCase())
      .join(token);
  }
  return hasNonAscii(label) ? urlToASCII(label.normalize('NFC')) : label.toLowerCase();
}

/**
 * Maps a decoded host to its lowercase ASCII (A-label) form and validates it
 * as a fully qualified DNS name. `localhost` is accepted as a single label.
 * Occurrences of `token` (the SCID token) are kept verbatim and checked as if
 * each were a SCID.
 */
function domainToAscii(decodedHost: string, token?: string): string {
  if (hasInvalidHostCharacter(decodedHost)) {
    throw new Error('Host contains invalid characters');
  }
  const host = decodedHost
    .split('.')
    .map((label) => asciiLabel(label, token))
    .join('.');
  if (isIPAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }
  if (isLocalhost(host)) {
    return host;
  }
  if (!hasFqdnShape(host, token, (label) => DNS_LABEL_PATTERN.test(label))) {
    throw new Error('Host must be a valid fully qualified domain');
  }
  return host;
}

/**
 * Checks the decoded host of a `did:webvh` identifier and returns its A-label
 * form. Identifiers created before A-label output may carry percent-encoded
 * U-labels. Those get runtime-independent checks only and return undefined;
 * IDNA conversion happens when the HTTPS URL is derived.
 */
function validateIdentifierHost(host: string, context: string, token?: string): string | undefined {
  if (!hasNonAscii(host)) {
    return domainToAscii(host, token);
  }
  if (token && host.split('.').some((label) => label.includes(token) && hasNonAscii(label))) {
    throw new Error(UNICODE_TOKEN_LABEL_ERROR);
  }
  const isValidLabel = (label: string) =>
    hasNonAscii(label) ? label.length <= 63 : DNS_LABEL_PATTERN.test(label.toLowerCase());
  if (hasInvalidHostCharacter(host) || !hasFqdnShape(host, token, isValidLabel)) {
    throw new Error(`${context} must include a valid fully qualified domain`);
  }
  return undefined;
}

function decodeHostComponent(host: string): string {
  try {
    return decodeURIComponent(host);
  } catch {
    throw new Error(`Invalid percent-encoding in host: ${host}`);
  }
}

/**
 * Splits a caller-supplied host or path segment around occurrences of the SCID
 * token (`{SCID}` on create, the SCID on update) and decodes each remaining part
 * exactly once. The token itself is never decoded, so an encoded `%7BSCID%7D`
 * stays literal text.
 */
function decodeAroundToken(value: string, token: string, errorMessage: string): string[] {
  return splitAroundToken(value, token).map((part) => {
    try {
      return decodeURIComponent(part);
    } catch {
      throw new Error(errorMessage);
    }
  });
}

/**
 * Decodes a caller-supplied host once and maps it to the canonical lowercase
 * A-label form. SCID token occurrences are kept verbatim (no lowercasing or
 * IDNA mapping).
 */
function canonicalHostComponent(rawHost: string, scid: string): string {
  const parts = decodeAroundToken(rawHost, scid, `Invalid percent-encoding in host: ${rawHost}`);
  // A token that appears only after decoding was percent-encoded by the caller.
  // It is literal text, and cannot be part of a valid domain.
  if (parts.some((part) => part.includes(scid))) {
    throw new Error('Host must be a valid fully qualified domain');
  }
  return domainToAscii(parts.join(scid), parts.length > 1 ? scid : undefined);
}

/** `port-number = 1*5DIGIT` in the spec ABNF, within the TCP range. */
function parsePortNumber(rawPort: string): number {
  const portNum = /^\d{1,5}$/.test(rawPort) ? Number(rawPort) : 0;
  if (portNum < 1 || portNum > 65535) {
    throw new Error(`Invalid port number: ${rawPort}`);
  }
  return portNum;
}

function toOptionalPaths(pathSegments: string[]): string[] | undefined {
  return pathSegments.length > 0 ? pathSegments : undefined;
}

function buildLocationKey(didDomainComponent: string, pathSegments: string[]): string {
  return pathSegments.length ? `${didDomainComponent}:${pathSegments.join(':')}` : didDomainComponent;
}

function toDidDomainComponent(host: string, port?: number): string {
  return port ? `${host}%3A${port}` : host;
}

function toParsedAddress(host: string, port?: number, paths: string[] = []): ParsedAddress {
  return {
    canonicalHost: host,
    canonicalPort: port,
    didDomainComponent: toDidDomainComponent(host, port),
    paths: toOptionalPaths(paths),
  };
}

function parseRawHostPort(input: string): { host: string; port?: number } {
  if (!input.includes(':')) {
    return { host: input };
  }

  const parts = input.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid host:port format');
  }

  return {
    host: parts[0],
    port: parsePortNumber(parts[1]),
  };
}

function parseEncodedPortComponent(value: string): { host: string; port?: number } {
  if (!ENCODED_PORT_SEPARATOR.test(value)) {
    return { host: value };
  }

  const parts = value.split(ENCODED_PORT_SEPARATOR);
  if (parts.length !== 2) {
    throw new Error('Invalid pre-encoded port separator');
  }

  const [host, rawPort] = parts;
  return { host, port: parsePortNumber(rawPort) };
}

export function validateMethodSpecificPathSegments(pathSegments: string[], context: string): void {
  for (const segment of pathSegments) {
    let decodedSegment: string;
    try {
      decodedSegment = decodeURIComponent(segment);
    } catch {
      throw new Error(`${context} contains invalid percent-encoding in path segment '${segment}'`);
    }

    if (decodedSegment === '') {
      throw new Error(`${context} must not contain empty path segments`);
    }

    if (decodedSegment === '.' || decodedSegment === '..') {
      throw new Error(`${context} must not contain dot-segments`);
    }

    if (decodedSegment.includes('/')) {
      throw new Error(`${context} must not contain decoded slash within a single path segment`);
    }

    if (decodedSegment.includes('\\')) {
      throw new Error(`${context} must not contain decoded backslash within a path segment`);
    }

    // WHATWG URL strips tab, CR, and LF before parsing, so a URL input is
    // checked here against the text it was built from, not the parsed path.
    if (hasControlCharacter(decodedSegment)) {
      throw new Error(`${context} must not contain decoded control characters within a path segment`);
    }

    if (decodedSegment !== decodedSegment.trim()) {
      throw new Error(`${context} must not contain leading or trailing whitespace in decoded path segment`);
    }
  }
}

/**
 * `encodeURIComponent` plus uppercase-hex encoding of the characters matched by
 * `alsoEncode`, which `encodeURIComponent` leaves as-is.
 */
const percentEncode = (value: string, alsoEncode: RegExp): string =>
  encodeURIComponent(value).replace(alsoEncode, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);

/**
 * Decodes a validated path segment once and re-encodes it with uppercase hex, as the
 * did:webvh v1.0 DID-to-HTTPS transformation requires. Only RFC 3986 unreserved
 * characters are left unencoded, so encoded sub-delimiters keep their meaning.
 */
function encodeUrlPathSegment(segment: string): string {
  return percentEncode(decodeURIComponent(segment), /[!'()*]/g);
}

/**
 * Canonicalizes a validated path segment (raw Unicode or already percent-encoded)
 * to DID Core idchars with uppercase hex. `~` is not an idchar, so it is encoded
 * too. Unicode text is left as given (no normalization). SCID token occurrences
 * are kept verbatim.
 */
function canonicalPathSegment(segment: string, context: string, scid: string): string {
  if (hasUnpairedSurrogate(segment)) {
    throw new Error(`${context} contains ill-formed Unicode (unpaired surrogate)`);
  }
  return decodeAroundToken(segment, scid, `${context} contains invalid percent-encoding in path segment '${segment}'`)
    .map((part) => percentEncode(part, /[!'()*~]/g))
    .join(scid);
}

/**
 * Splits a `did:webvh` string (identifier or `{SCID}` template) into its parts.
 * The host is decoded once; the path segments are validated and returned as given.
 */
function parseDidForm(
  input: string,
  context: string,
  allowPlaceholder: boolean
): { scid: string; encodedHost: string; host: string; port?: number; paths: string[] } {
  const parts = input.substring(DID_PREFIX.length).split(':');
  if (parts.length < 2) {
    throw new Error('Invalid did:webvh identifier: must contain SCID (or {SCID} placeholder) and domain');
  }

  // DID Core idchars are ASCII only, so Unicode text must be percent-encoded.
  if (hasNonAscii(input)) {
    throw new Error(`${context} must be a valid did:webvh identifier (non-ASCII characters must be percent-encoded)`);
  }

  const [scid, domainPart, ...pathParts] = parts;

  if (!SCID_PATTERN.test(scid) && !(allowPlaceholder && scid === SCID_PLACEHOLDER)) {
    throw new Error(`${context} must include a valid SCID`);
  }

  // `webvh-path-segment = 1*idchar`: a segment of a did:webvh string is taken
  // as written, so it has to be DID Core idchars already (the placeholder is
  // restored to a SCID, which is idchars, before the DID is produced).
  const token = allowPlaceholder ? SCID_PLACEHOLDER : undefined;
  for (const segment of pathParts) {
    if (!splitAroundToken(segment, token).every((part) => part === '' || DID_PATH_SEGMENT_PATTERN.test(part))) {
      throw new Error(`${context} contains characters that are not DID Core idchars in path segment '${segment}'`);
    }
  }

  validateMethodSpecificPathSegments(pathParts, context);

  // Detect double encoding
  if (isDoubleEncoded(domainPart)) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  // Extract port from domain if %3A-encoded
  const { host: encodedHost, port } = parseEncodedPortComponent(domainPart);

  // Percent-encoding in the host is for the bytes of a U-label only. An
  // encoded ASCII character would make a second identifier for one location.
  if (ENCODED_ASCII_PATTERN.test(encodedHost)) {
    throw new Error(`${context} must not percent-encode ASCII characters in the host`);
  }

  return { scid, encodedHost, host: decodeHostComponent(encodedHost), port, paths: pathParts };
}

/**
 * Takes the URL input's host and path segments as written, before the runtime's URL
 * lowercases and IDNA-maps the host and percent-encodes the path (which would
 * turn a `{SCID}` placeholder into literal `%7BSCID%7D`).
 */
function rawUrlParts(input: string): { host: string; pathSegments: string[] } {
  const [authority, ...pathSegments] = input.slice(input.indexOf('://') + 3).split('/');
  const portSeparator = authority.lastIndexOf(':');
  return {
    host: portSeparator === -1 ? authority : authority.slice(0, portSeparator),
    pathSegments: pathSegments.filter((segment) => segment.length > 0),
  };
}

function parseUrlAddress(input: string, scid: string): ParsedAddress {
  let url: URL;
  try {
    url = new URL(input);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    throw new Error(`Invalid URL: ${message}`);
  }

  if (url.protocol === 'http:' && !isLocalhost(url.hostname)) {
    throw new Error('HTTP is only allowed for localhost; use HTTPS for non-local hosts');
  }
  if (url.hash || url.search) {
    throw new Error('URL input must not include query or fragment components');
  }
  // Checked before the host is read from the raw text, where userinfo would
  // otherwise be mistaken for the host.
  if (url.username || url.password) {
    throw new Error('URL input must not include username or password');
  }
  if (isIPAddress(url.hostname)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  const port = url.port ? parseInt(url.port, 10) : undefined;
  const { host, pathSegments } = rawUrlParts(input);

  validateMethodSpecificPathSegments(pathSegments, 'URL pathname');

  return toParsedAddress(
    canonicalHostComponent(host, scid),
    port,
    pathSegments.map((segment) => canonicalPathSegment(segment, 'URL pathname', scid))
  );
}

/**
 * Resolves the DID being produced from an address and the caller's path
 * options. Paths embedded in the address come back canonical from the parser.
 * `paths` (appended to them) and `priorPaths` (inherited when neither is
 * given) may be raw Unicode, lowercase hex, or a non-canonical form from an
 * older entry, so they are validated and canonicalized here.
 */
const normalizeDidAddressWithPaths = (
  address: string,
  scid: string,
  { paths, priorPaths = [] }: { paths?: string[]; priorPaths?: string[] },
  context: string
): ParsedDidWebvhIdentifier & { controller: string } => {
  // did:webvh v1.0 defines the `{SCID}` placeholder only for DID creation. Once
  // the SCID exists (update/migration) callers must supply the actual value.
  if (
    scid !== SCID_PLACEHOLDER &&
    [address, ...(paths ?? []), ...priorPaths].some((v) => v.includes(SCID_PLACEHOLDER))
  ) {
    throw new Error(`${context} must not contain the {SCID} placeholder once the SCID has been generated`);
  }
  const parsed = parseCanonicalAddress(address, DEFAULT_CONTEXT, { scid });
  const addressPaths = parsed.paths ?? [];
  const canonicalize = (segments: string[]) => {
    validateMethodSpecificPathSegments(segments, context);
    return segments.map((segment) => canonicalPathSegment(segment, context, scid));
  };

  let canonicalPaths: string[];
  if (paths !== undefined) {
    canonicalPaths = [...addressPaths, ...canonicalize(paths)];
  } else {
    canonicalPaths = addressPaths.length ? addressPaths : canonicalize(priorPaths);
  }

  const locationKey = buildLocationKey(parsed.didDomainComponent, canonicalPaths);

  return {
    scid,
    didDomainComponent: parsed.didDomainComponent,
    paths: toOptionalPaths(canonicalPaths),
    locationKey,
    controller: `did:${METHOD}:${scid}:${locationKey}`,
  };
};

/** Create-time address normalization: explicit paths append to any address-embedded paths. */
export function normalizeCreateDidAddress({
  address,
  scid,
  paths,
  context,
}: {
  address: string;
  scid: string;
  paths?: string[];
  context: string;
}): ParsedDidWebvhIdentifier & { controller: string } {
  return normalizeDidAddressWithPaths(address, scid, { paths }, context);
}

/**
 * Update-time address normalization: explicit `paths` win (combined with any
 * address-embedded paths); otherwise address-embedded paths; otherwise the
 * prior entry's paths are inherited, so re-passing a bare domain on a pathed
 * DID doesn't silently drop them.
 */
export function normalizeUpdateDidAddress({
  address,
  scid,
  paths,
  priorPaths,
  context,
}: {
  address: string;
  scid: string;
  paths?: string[];
  priorPaths: string[];
  context: string;
}): ParsedDidWebvhIdentifier & { controller: string } {
  return normalizeDidAddressWithPaths(address, scid, { paths, priorPaths }, context);
}

/**
 * Parses a `did:webvh` identifier or `{SCID}` template, an `https://` (or
 * `http://localhost`) URL, or a bare `host[:port]` string into its canonical
 * host / port / path parts. In every form the host is decoded once,
 * NFC-normalized, and emitted as a lowercase A-label; path segments are
 * emitted as idchars with uppercase hex. Raw non-ASCII text is rejected in the
 * `did:webvh` form only.
 *
 * `context` labels path-validation errors raised for the `did:webvh` input
 * form, so callers can surface the identifier's provenance (for example
 * `"last entry state.id"`).
 *
 * `scid` names the token kept verbatim in the host and path segments: `{SCID}`
 * on create (the default), the actual SCID on update. On update a `did:webvh`
 * input has to carry that SCID; a different SCID names a different DID.
 */
export function parseCanonicalAddress(
  input: string,
  context: string = DEFAULT_CONTEXT,
  { scid = SCID_PLACEHOLDER }: { scid?: string } = {}
): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  // Checked before URL parsing, which would silently replace an unpaired
  // surrogate with U+FFFD.
  if (hasUnpairedSurrogate(input)) {
    throw new Error('Address input contains ill-formed Unicode (unpaired surrogate)');
  }

  if (hasFragmentOrQuery(input) && !input.startsWith('http://') && !input.startsWith('https://')) {
    throw new Error('Address input must not include query or fragment components');
  }

  // Parse did:webvh form.
  if (input.startsWith(DID_PREFIX)) {
    const isTemplate = scid === SCID_PLACEHOLDER;
    const { scid: scidSlot, encodedHost, port, paths } = parseDidForm(input, context, isTemplate);
    if (!isTemplate && scidSlot !== scid) {
      throw new Error(`${context} must carry the SCID of the DID being updated`);
    }
    return toParsedAddress(
      canonicalHostComponent(encodedHost, scid),
      port,
      paths.map((segment) => canonicalPathSegment(segment, context, scid))
    );
  }

  // Parse URL form: HTTPS everywhere, with localhost-only HTTP for local testing.
  if (input.startsWith('https://') || input.startsWith('http://')) {
    return parseUrlAddress(input, scid);
  }

  // Parse domain string form (host or host:port)
  // Detect double encoding
  if (isDoubleEncoded(input)) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  const hostAndPort = ENCODED_PORT_SEPARATOR.test(input) ? parseEncodedPortComponent(input) : parseRawHostPort(input);

  return toParsedAddress(canonicalHostComponent(hostAndPort.host, scid), hostAndPort.port);
}

/**
 * Single parse pass over a `did:webvh` identifier. Returns the public
 * {@link ParsedDidWebvhIdentifier} shape plus the decoded host, its A-label
 * form (undefined for a percent-encoded U-label identifier, whose IDNA
 * mapping is deferred to URL derivation), and the port, so URL derivation can
 * reuse them instead of re-splitting `didDomainComponent`. The domain
 * component is kept as encoded in the identifier (apart from an uppercase
 * `%3A` port separator), so a percent-encoded U-label identifier keeps its
 * form. A creation template keeps its `{SCID}` placeholders, each checked as
 * if it were a SCID.
 */
function parseDidWebvhAddress(
  did: string,
  context: string,
  allowScidPlaceholder = false
): { identifier: ParsedDidWebvhIdentifier; host: string; asciiHost?: string; port?: number } {
  const didParts = did.split(':');

  if (didParts.length < 4 || didParts[0] !== 'did' || didParts[1] !== METHOD) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  if (hasFragmentOrQuery(did)) {
    throw new Error('Address input must not include query or fragment components');
  }

  const { scid, encodedHost, host, port, paths } = parseDidForm(did, context, allowScidPlaceholder);
  const asciiHost = validateIdentifierHost(host, context, allowScidPlaceholder ? SCID_PLACEHOLDER : undefined);

  const didDomainComponent = toDidDomainComponent(encodedHost, port);

  return {
    identifier: {
      scid,
      didDomainComponent,
      paths: toOptionalPaths(paths),
      locationKey: buildLocationKey(didDomainComponent, paths),
    },
    host,
    asciiHost,
    port,
  };
}

/** `allowScidPlaceholder` accepts the `{SCID}` creation-template form in place of a real SCID. */
export function parseDidWebvhIdentifier(
  did: string,
  context: string,
  { allowScidPlaceholder = false }: { allowScidPlaceholder?: boolean } = {}
): ParsedDidWebvhIdentifier {
  return parseDidWebvhAddress(did, context, allowScidPlaceholder).identifier;
}

const buildBaseUrl = ({
  identifier,
  host,
  asciiHost = domainToAscii(host),
  port,
}: ReturnType<typeof parseDidWebvhAddress>) => {
  const protocol = schemeForHost(asciiHost);
  const normalizedHost = port ? `${asciiHost}:${port}` : asciiHost;
  const path = identifier.paths?.map(encodeUrlPathSegment).join('/') ?? '';

  return `${protocol}://${normalizedHost}${path ? `/${path}` : ''}`;
};

export const getBaseUrl = (id: string) => buildBaseUrl(parseDidWebvhAddress(id, 'did:webvh identifier'));

export const getFileUrl = (id: string) => {
  const parsed = parseDidWebvhAddress(id, 'did:webvh identifier');
  const baseUrl = buildBaseUrl(parsed);

  if (parsed.identifier.paths?.length) {
    return `${baseUrl}/did.jsonl`;
  }

  return `${baseUrl}/.well-known/did.jsonl`;
};
