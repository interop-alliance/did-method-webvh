import { config } from './config.js';
import { METHOD } from './constants.js';
import { findVerificationMethod } from './did-document.js';
import type { DIDLog, ParsedDidKeyVerificationMethod, WitnessProofFileEntry } from './interfaces.js';
import { resolveDIDFromLog } from './method.js';
import { multibaseDecode } from './utils/multiformats.js';

const DID_KEY_PREFIX = 'did:key:';

function validateDidKeyMultibase(keyMultibase: string): void {
  if (!keyMultibase) {
    throw new Error('Malformed did:key identifier');
  }

  try {
    multibaseDecode(keyMultibase);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Malformed did:key identifier: ${message}`);
  }
}

export function parseDidKeyDid(input: string): { did: string; keyMultibase: string } {
  if (typeof input !== 'string') {
    throw new Error('did:key DID must be a string');
  }

  const match = input.match(/^did:key:([^#/?]+)$/);
  if (!match) {
    throw new Error('Malformed did:key DID');
  }

  const keyMultibase = match[1];
  validateDidKeyMultibase(keyMultibase);

  return {
    did: `${DID_KEY_PREFIX}${keyMultibase}`,
    keyMultibase,
  };
}

export function parseDidKeyVerificationMethod(input: string): ParsedDidKeyVerificationMethod {
  if (typeof input !== 'string') {
    throw new Error('did:key verificationMethod must be a string');
  }

  if (input.startsWith('#')) {
    throw new Error('did:key verificationMethod must be an absolute DID URL');
  }

  const match = input.match(/^did:key:([^#/?]+)(?:#([^#/?]+))?$/);
  if (!match) {
    throw new Error('Malformed did:key verificationMethod');
  }

  const parsedDid = parseDidKeyDid(`${DID_KEY_PREFIX}${match[1]}`);
  const fragment = match[2];

  // If fragment is present, it MUST equal the body multibase exactly
  if (fragment && fragment !== parsedDid.keyMultibase) {
    throw new Error(
      `did:key verificationMethod fragment must equal body multibase. ` +
        `Expected fragment '${parsedDid.keyMultibase}' but got '${fragment}'`
    );
  }

  return {
    did: parsedDid.did,
    fragment,
    keyMultibase: parsedDid.keyMultibase,
  };
}

// Canonical address parser for strict parity with didwebvh-rs
interface ParsedAddress {
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

export function normalizeDidAddress({
  address,
  scid,
  paths,
  fallbackPaths,
  context,
}: {
  address: string;
  scid: string;
  paths?: string[];
  fallbackPaths?: string[];
  context: string;
}): ParsedDidWebvhIdentifier & { controller: string } {
  const parsed = parseCanonicalAddress(address);
  const addressPaths = parsed.paths || [];
  const resolvedPaths =
    fallbackPaths !== undefined
      ? paths !== undefined
        ? [...addressPaths, ...paths]
        : addressPaths.length
          ? addressPaths
          : fallbackPaths
      : [...addressPaths, ...(paths || [])];

  validateMethodSpecificPathSegments(resolvedPaths, context);

  const locationKey = buildLocationKey(parsed.didDomainComponent, resolvedPaths);

  return {
    scid,
    didDomainComponent: parsed.didDomainComponent,
    paths: toOptionalPaths(resolvedPaths),
    locationKey,
    controller: `did:${METHOD}:${scid}:${locationKey}`,
  };
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

    if (hasFragmentOrQuery(domainPart) || pathParts.some((segment) => hasFragmentOrQuery(segment))) {
      throw new Error('did:webvh identifier must not include query or fragment components');
    }

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
      if (url.protocol === 'http:' && url.hostname !== 'localhost') {
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

  if (hasFragmentOrQuery(input)) {
    throw new Error('Domain input must not include query or fragment components');
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

const toASCII = (domain: string): string => {
  try {
    const scheme = domain.includes('localhost') ? 'http' : 'https';
    return new URL(`${scheme}://${domain}`).hostname;
  } catch {
    return domain;
  }
};

export const readLogFromDisk = async (path: string): Promise<DIDLog> => {
  const fs = await getFS();
  return readLogFromString(fs.readFileSync(path, 'utf8'));
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

    fs.writeFileSync(path, `${JSON.stringify(log[0])}\n`);

    for (let i = 1; i < log.length; i++) {
      fs.appendFileSync(path, `${JSON.stringify(log[i])}\n`);
    }
  } catch (error) {
    console.error('Error writing log to disk:', error);
    throw error;
  }
};

export const maybeWriteTestLog = async (did: string, log: DIDLog) => {
  if (!config.isTestEnvironment) return;
  try {
    const fileSafe = did.replace(/[^a-zA-Z0-9]+/g, '_');
    const path = `./test/logs/${fileSafe}.jsonl`;
    await writeLogToDisk(path, log);
  } catch (error) {
    console.error('Error writing test log:', error);
  }
};

/**
 * Parses a `did:webvh` identifier for URL derivation, rejecting query/fragment
 * contamination up front. `parseCanonicalAddress` already decoded the host and
 * port, so no re-parsing of `didDomainComponent` is needed downstream.
 */
const parseDidWebvhIdentifierForUrl = (id: string) => {
  if (hasFragmentOrQuery(id)) {
    throw new Error('did:webvh identifier must not include query or fragment components');
  }

  return parseDidWebvhAddress(id, 'did:webvh identifier');
};

const buildBaseUrl = ({ identifier, address }: ReturnType<typeof parseDidWebvhIdentifierForUrl>) => {
  // This fork allows http for localhost (local testing); HTTPS everywhere else.
  const protocol = address.canonicalHost === 'localhost' ? 'http' : 'https';
  const host = toASCII(address.canonicalHost.normalize('NFC'));
  const normalizedHost = address.canonicalPort ? `${host}:${address.canonicalPort}` : host;
  const path = identifier.paths?.join('/') ?? '';

  return `${protocol}://${normalizedHost}${path ? `/${path}` : ''}`;
};

export const getBaseUrl = (id: string) => buildBaseUrl(parseDidWebvhIdentifierForUrl(id));

export const getFileUrl = (id: string) => {
  const parsed = parseDidWebvhIdentifierForUrl(id);
  const baseUrl = buildBaseUrl(parsed);

  if (parsed.identifier.paths?.length) {
    return `${baseUrl}/did.jsonl`;
  }

  return `${baseUrl}/.well-known/did.jsonl`;
};

export async function fetchLogFromIdentifier(identifier: string): Promise<DIDLog> {
  try {
    const url = getFileUrl(identifier);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const text = (await response.text()).trim();
    if (!text) {
      throw new Error(`DID log not found for ${identifier}`);
    }
    return text.split('\n').map((line) => JSON.parse(line));
  } catch (error) {
    console.error('Error fetching DID log:', error);
    throw error;
  }
}

export const resolveVM = async (vm: string) => {
  try {
    if (vm.startsWith('did:key:')) {
      const parsedVerificationMethod = parseDidKeyVerificationMethod(vm);
      return { publicKeyMultibase: parsedVerificationMethod.keyMultibase };
    } else if (vm.startsWith('did:webvh:')) {
      const url = getFileUrl(vm.split('#')[0]);
      const didLog = await (await fetch(url)).text();
      const logEntries: DIDLog = didLog
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l));
      const { doc } = await resolveDIDFromLog(logEntries, { verificationMethod: vm });
      if (!doc) {
        throw new Error(`Verification method ${vm} not found`);
      }
      return findVerificationMethod(doc, vm);
    }
    throw new Error(`Verification method ${vm} not found`);
  } catch (e) {
    throw new Error(`Error resolving VM ${vm}`);
  }
};

export async function fetchWitnessProofs(did: string): Promise<WitnessProofFileEntry[]> {
  try {
    const url = getFileUrl(did).replace('did.jsonl', 'did-witness.json');

    const response = await fetch(url);
    if (!response.ok) {
      return [];
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching witness proofs:', error);
    return [];
  }
}

// Re-exported from the leaf module so existing importers of `./utils.js` are
// unaffected while `did-document.ts` can import it without an import cycle.
export { replaceValueInObject } from './utils/object.js';
