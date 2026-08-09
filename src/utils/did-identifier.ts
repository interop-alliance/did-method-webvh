/**
 * did:webvh identifier grammar and resolution-URL derivation.
 *
 * Leaf module (imports only constants) so higher layers -- `did-document.ts`,
 * the method implementations, and `utils.ts` -- can all share one parser
 * without import cycles.
 */
import { METHOD } from '../constants.js';

// Canonical address parser for strict parity with didwebvh-rs
export interface ParsedAddress {
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

function isIPAddress(host: string): boolean {
  // Reject IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  // Reject IPv6 (with or without brackets)
  const bare = host.replace(/^\[|\]$/g, '');
  if (/^[0-9a-f:]+$/i.test(bare)) return true;
  return false;
}

function isDoubleEncoded(value: string): boolean {
  // Detect %25 (which is percent-encoded %)
  return value.includes('%25');
}

function hasFragmentOrQuery(value: string): boolean {
  return value.includes('#') || value.includes('?');
}

function decodeHostComponent(host: string): string {
  try {
    return decodeURIComponent(host);
  } catch {
    throw new Error(`Invalid percent-encoding in host: ${host}`);
  }
}

function parsePortNumber(rawPort: string): number {
  const portNum = parseInt(rawPort, 10);
  if (Number.isNaN(portNum) || portNum <= 0 || portNum > 65535) {
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
  const encodedSeparator = /%3a/i;
  if (!encodedSeparator.test(value)) {
    return { host: value };
  }

  const parts = value.split(encodedSeparator);
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

    if (decodedSegment === '.' || decodedSegment === '..') {
      throw new Error(`${context} must not contain dot-segments`);
    }

    if (decodedSegment.includes('/')) {
      throw new Error(`${context} must not contain decoded slash within a single path segment`);
    }

    if (decodedSegment.includes('\\')) {
      throw new Error(`${context} must not contain decoded backslash within a path segment`);
    }

    if (decodedSegment.includes('\u0000')) {
      throw new Error(`${context} must not contain decoded NUL character within a path segment`);
    }

    if (decodedSegment !== decodedSegment.trim()) {
      throw new Error(`${context} must not contain leading or trailing whitespace in decoded path segment`);
    }
  }
}

const normalizeDidAddressWithPaths = (
  address: string,
  scid: string,
  resolvePaths: (addressPaths: string[]) => string[],
  context: string
): ParsedDidWebvhIdentifier & { controller: string } => {
  const parsed = parseCanonicalAddress(address);
  const resolvedPaths = resolvePaths(parsed.paths ?? []);

  validateMethodSpecificPathSegments(resolvedPaths, context);

  const locationKey = buildLocationKey(parsed.didDomainComponent, resolvedPaths);

  return {
    scid,
    didDomainComponent: parsed.didDomainComponent,
    paths: toOptionalPaths(resolvedPaths),
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
  return normalizeDidAddressWithPaths(address, scid, (addressPaths) => [...addressPaths, ...(paths ?? [])], context);
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
  return normalizeDidAddressWithPaths(
    address,
    scid,
    (addressPaths) =>
      paths !== undefined ? [...addressPaths, ...paths] : addressPaths.length ? addressPaths : priorPaths,
    context
  );
}

/**
 * Parses a `did:webvh` identifier, an `https://` (or `http://localhost`) URL,
 * or a bare `host[:port]` string into its canonical host / port / path parts.
 *
 * `context` labels path-validation errors raised for the `did:webvh` input
 * form, so callers can surface the identifier's provenance (for example
 * `"last entry state.id"`).
 */
export function parseCanonicalAddress(input: string, context: string = 'did:webvh identifier'): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  if (hasFragmentOrQuery(input) && !input.startsWith('http://') && !input.startsWith('https://')) {
    throw new Error('Address input must not include query or fragment components');
  }

  // Parse did:webvh form
  if (input.startsWith('did:webvh:')) {
    const parts = input.substring(10).split(':');
    if (parts.length < 2) {
      throw new Error('Invalid did:webvh identifier: must contain SCID (or {SCID} placeholder) and domain');
    }

    const domainPart = parts[1];
    const pathParts = parts.slice(2);

    validateMethodSpecificPathSegments(pathParts, context);

    // Detect double encoding
    if (isDoubleEncoded(domainPart)) {
      throw new Error('Domain is double-encoded (detected %25)');
    }

    // Extract port from domain if %3A-encoded
    const parsedPort = parseEncodedPortComponent(domainPart);
    const host = decodeHostComponent(parsedPort.host);
    const port = parsedPort.port;

    if (isIPAddress(host)) {
      throw new Error('IP addresses are not allowed as hosts');
    }

    return toParsedAddress(host, port, pathParts);
  }

  // Parse URL form: HTTPS everywhere, with localhost-only HTTP for local testing.
  if (input.startsWith('https://') || input.startsWith('http://')) {
    try {
      const url = new URL(input);
      if (url.protocol === 'http:' && !isLocalhost(url.hostname)) {
        throw new Error('HTTP is only allowed for localhost; use HTTPS for non-local hosts');
      }
      if (url.hash || url.search) {
        throw new Error('URL input must not include query or fragment components');
      }
      const host = url.hostname;
      const port = url.port ? parseInt(url.port, 10) : undefined;

      if (isIPAddress(host)) {
        throw new Error('IP addresses are not allowed as hosts');
      }

      const pathParts = url.pathname && url.pathname !== '/' ? url.pathname.split('/').filter((p) => p.length > 0) : [];

      validateMethodSpecificPathSegments(pathParts, 'URL pathname');

      return toParsedAddress(host, port, pathParts);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (message.includes('not allowed')) throw e;
      throw new Error(`Invalid URL: ${message}`);
    }
  }

  // Parse domain string form (host or host:port)
  // Detect double encoding
  if (isDoubleEncoded(input)) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  const hostAndPort = /%3a/i.test(input) ? parseEncodedPortComponent(input) : parseRawHostPort(input);
  const host = decodeHostComponent(hostAndPort.host);
  const port = hostAndPort.port;

  if (isIPAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  return toParsedAddress(host, port);
}

/**
 * Single parse pass over a `did:webvh` identifier. Returns both the public
 * {@link ParsedDidWebvhIdentifier} shape and the underlying {@link ParsedAddress},
 * so URL derivation can reuse the already-decoded host and port instead of
 * re-splitting `didDomainComponent`.
 */
function parseDidWebvhAddress(
  did: string,
  context: string
): { identifier: ParsedDidWebvhIdentifier; address: ParsedAddress } {
  const didParts = did.split(':');

  if (didParts.length < 4 || didParts[0] !== 'did' || didParts[1] !== METHOD) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const scid = didParts[2];
  if (!scid) {
    throw new Error(`${context} must include SCID segment`);
  }

  const address = parseCanonicalAddress(did, context);
  const paths = address.paths ?? [];

  return {
    identifier: {
      scid,
      didDomainComponent: address.didDomainComponent,
      paths: toOptionalPaths(paths),
      locationKey: buildLocationKey(address.didDomainComponent, paths),
    },
    address,
  };
}

export function parseDidWebvhIdentifier(did: string, context: string): ParsedDidWebvhIdentifier {
  return parseDidWebvhAddress(did, context).identifier;
}

// The scheme has no effect on hostname parsing (http and https are both
// special schemes), so IDNA/punycode conversion is scheme-independent.
const toASCII = (domain: string): string => {
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return domain;
  }
};

const buildBaseUrl = ({ identifier, address }: ReturnType<typeof parseDidWebvhAddress>) => {
  const protocol = schemeForHost(address.canonicalHost);
  const host = toASCII(address.canonicalHost.normalize('NFC'));
  const normalizedHost = address.canonicalPort ? `${host}:${address.canonicalPort}` : host;
  const path = identifier.paths?.join('/') ?? '';

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
