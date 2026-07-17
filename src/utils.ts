import { config } from './config.js';
import { BASE_CONTEXT, METHOD } from './constants.js';
import type {
  CreateDIDInterface,
  DIDDoc,
  DIDLog,
  ParsedDidKeyVerificationMethod,
  VerificationMethod,
  WitnessProofFileEntry,
} from './interfaces.js';
import { resolveDIDFromLog } from './method.js';
import { canonicalizeStrict } from './utils/canonicalize.js';
import { createHash } from './utils/crypto.js';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm, multibaseDecode } from './utils/multiformats.js';

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

export function parseCanonicalAddress(input: string): ParsedAddress {
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

    validateMethodSpecificPathSegments(pathParts, 'did:webvh identifier');

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

export function parseDidWebvhIdentifier(did: string, context: string): ParsedDidWebvhIdentifier {
  const parsedAddress = parseCanonicalAddress(did);
  const didParts = did.split(':');

  if (didParts.length < 4 || didParts[0] !== 'did' || didParts[1] !== METHOD) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const scid = didParts[2];
  if (!scid) {
    throw new Error(`${context} must include SCID segment`);
  }

  const locationKey = parsedAddress.paths?.length
    ? `${parsedAddress.didDomainComponent}:${parsedAddress.paths.join(':')}`
    : parsedAddress.didDomainComponent;

  return {
    scid,
    didDomainComponent: parsedAddress.didDomainComponent,
    paths: parsedAddress.paths,
    locationKey,
  };
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

export const DID_PLACEHOLDER = '{DID}';

export function validateCreateDidDocument(didDocument: DIDDoc): void {
  if (!didDocument || typeof didDocument !== 'object') {
    throw new Error('didDocument must be an object');
  }
  if (typeof didDocument.id !== 'string') {
    throw new Error("didDocument 'id' field must be a string");
  }
  if (!didDocument.id.includes('{SCID}') && !didDocument.id.includes(DID_PLACEHOLDER)) {
    throw new Error("didDocument.id must contain a '{SCID}' or '{DID}' placeholder");
  }
}

export function replaceCreateDidPlaceholders<T>(input: T, scid: string, did: string): T {
  const withScid = replaceValueInObject(input, '{SCID}', scid);
  return replaceValueInObject(withScid, DID_PLACEHOLDER, did) as T;
}

export function convertWebvhIdToWebId(id: string): string {
  const parts = id.split(':');
  if (parts.length < 4 || parts[0] !== 'did' || parts[1] !== 'webvh') {
    throw new Error(`Invalid did:webvh id '${id}'`);
  }
  return `did:web:${parts.slice(3).join(':')}`;
}

export function enrichAlsoKnownAs(doc: DIDDoc, did: string, opts: { alsoKnownAsWeb?: boolean }): DIDDoc {
  if (doc.alsoKnownAs !== undefined && !Array.isArray(doc.alsoKnownAs)) {
    throw new Error('alsoKnownAs is not an array');
  }

  const aliases = Array.isArray(doc.alsoKnownAs) ? [...doc.alsoKnownAs] : [];
  const addAlias = (alias: string) => {
    if (!aliases.includes(alias)) {
      aliases.push(alias);
    }
  };

  if (opts.alsoKnownAsWeb) {
    addAlias(convertWebvhIdToWebId(did));
  }

  if (aliases.length === 0) {
    return doc;
  }

  return {
    ...doc,
    alsoKnownAs: aliases,
  };
}

export function generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc {
  let webDoc = structuredClone(didwebvhDoc);

  const scidPrefix = didwebvhDid.replace(/^did:webvh:([^:]+):.*$/, 'did:webvh:$1:');
  webDoc = replaceValueInObject(webDoc, scidPrefix, 'did:web:');

  const webDid = webDoc.id as string;
  const aliases = (Array.isArray(webDoc.alsoKnownAs) ? [...webDoc.alsoKnownAs] : []).filter(
    (alias: string) => alias !== webDid
  );

  if (!aliases.includes(didwebvhDid)) {
    aliases.push(didwebvhDid);
  }

  return {
    ...webDoc,
    alsoKnownAs: [...new Set(aliases)],
  };
}

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

export const getBaseUrl = (id: string) => {
  if (hasFragmentOrQuery(id)) {
    throw new Error('did:webvh identifier must not include query or fragment components');
  }

  const parsed = parseCanonicalAddress(id);
  // This fork allows http for localhost (local testing); HTTPS everywhere else.
  const protocol = parsed.canonicalHost === 'localhost' ? 'http' : 'https';
  const host = toASCII(parsed.canonicalHost.normalize('NFC'));
  const normalizedHost = parsed.canonicalPort ? `${host}:${parsed.canonicalPort}` : host;
  const path = parsed.paths?.join('/') ?? '';

  return `${protocol}://${normalizedHost}${path ? `/${path}` : ''}`;
};

export const getFileUrl = (id: string) => {
  const baseUrl = getBaseUrl(id);
  const domainEndIndex = baseUrl.indexOf('/', baseUrl.indexOf('://') + 3);

  if (domainEndIndex !== -1) {
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

export const createDate = (created?: Date | string) =>
  new Date(created ?? Date.now()).toISOString().replace(/\.\d{1,3}Z$/, 'Z');

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export const createSCID = async (logEntryHash: string): Promise<string> => {
  return logEntryHash;
};

// Cache for deriveHash operations to avoid redundant computation. Bounded with
// a simple FIFO eviction so a long-lived process (e.g. a resolver serving many
// DIDs, keyed by full log entries) cannot grow it without limit.
export const HASH_CACHE_MAX_ENTRIES = 500;
const hashCache = new Map<string, string>();

/** @internal Test-only accessor for the bounded deriveHash memo cache size. */
export const getHashCacheSizeForTests = (): number => hashCache.size;

function getCachedHash(input: unknown): string | undefined {
  try {
    const key = JSON.stringify(input);
    return hashCache.get(key);
  } catch {
    return undefined;
  }
}

function setCachedHash(input: unknown, hash: string): void {
  try {
    const key = JSON.stringify(input);
    hashCache.set(key, hash);
    // Map preserves insertion order, so the first key is the oldest insertion.
    if (hashCache.size > HASH_CACHE_MAX_ENTRIES) {
      const oldestKey = hashCache.keys().next().value;
      if (oldestKey !== undefined) {
        hashCache.delete(oldestKey);
      }
    }
  } catch {
    // Ignore caching errors
  }
}

// Input must be strict JSON-compatible and must not contain explicit undefined values.
export async function deriveHash(input: unknown): Promise<string> {
  const cached = getCachedHash(input);
  if (cached) {
    return cached;
  }
  const data = canonicalizeStrict(input);
  const hash = await createHash(data);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  const result = encodeBase58Btc(multihash);
  setCachedHash(input, result);
  return result;
}

/**
 * Derives a `nextKeyHashes` entry from an update key (its `did:key`
 * multibase). Returns the spec's bare base58btc multihash, NOT `z`-prefixed
 * multibase -- did:webvh 1.0 mandates `nextKeyHashes` entries be multihash
 * base58btc. Do NOT multibase-encode the result; the asymmetry with every
 * other `z`-prefixed value in this API is intentional and spec-required.
 */
export const deriveNextKeyHash = async (input: string): Promise<string> => {
  const hash = await createHash(input);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  return encodeBase58Btc(multihash);
};

export const createDIDDoc = async (options: CreateDIDInterface): Promise<{ doc: DIDDoc }> => {
  const { controller } = options;
  const all = normalizeVMs(options.verificationMethods, controller, options.vmIdFragment);

  // Create the base document
  const doc: DIDDoc = {
    '@context': options.context || BASE_CONTEXT,
    id: controller,
    controller,
  };

  // Add verification methods and relationships from normalizeVMs
  if (all && typeof all === 'object') {
    if (all.verificationMethod) {
      doc.verificationMethod = all.verificationMethod;
    }

    if (all.authentication) {
      doc.authentication = all.authentication;
    }

    if (all.assertionMethod) {
      doc.assertionMethod = all.assertionMethod;
    }

    if (all.keyAgreement) {
      doc.keyAgreement = all.keyAgreement;
    }

    if (all.capabilityDelegation) {
      doc.capabilityDelegation = all.capabilityDelegation;
    }

    if (all.capabilityInvocation) {
      doc.capabilityInvocation = all.capabilityInvocation;
    }
  }

  // Add direct properties from options
  if (options.authentication) {
    doc.authentication = options.authentication;
  }

  if (options.assertionMethod) {
    doc.assertionMethod = options.assertionMethod;
  }

  if (options.keyAgreement) {
    doc.keyAgreement = options.keyAgreement;
  }

  if (options.capabilityDelegation) {
    doc.capabilityDelegation = options.capabilityDelegation;
  }

  if (options.capabilityInvocation) {
    doc.capabilityInvocation = options.capabilityInvocation;
  }

  if (options.alsoKnownAs) {
    doc.alsoKnownAs = options.alsoKnownAs;
  }

  if (options.services) {
    doc.service = options.services;
  }

  return { doc };
};

// Helper function to generate a random string (replacement for nanoid)
export const generateRandomId = (length: number = 8): string => {
  const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
};

/**
 * Builds a verification-method id (`<did>#<fragment>`). The fragment is derived
 * from `publicKeyMultibase`: `'short'` (default, and the historical behavior)
 * uses its last 8 characters; `'multibase'` uses the full multibase, yielding a
 * self-describing `#<publicKeyMultibase>` fragment. When no `publicKeyMultibase`
 * is present, a random 8-char id is used regardless of mode.
 */
export const createVMID = (
  vm: VerificationMethod,
  did: string | null,
  vmIdFragment: 'short' | 'multibase' = 'short'
) => {
  const fragment =
    vmIdFragment === 'multibase' && vm.publicKeyMultibase
      ? vm.publicKeyMultibase
      : vm.publicKeyMultibase?.slice(-8) || generateRandomId(8);
  return `${did ?? ''}#${fragment}`;
};

type NormalizedVerificationMethods = Required<
  Pick<
    DIDDoc,
    | 'verificationMethod'
    | 'authentication'
    | 'assertionMethod'
    | 'keyAgreement'
    | 'capabilityDelegation'
    | 'capabilityInvocation'
  >
>;

export const normalizeVMs = (
  verificationMethod: VerificationMethod[] | undefined,
  did: string | null = null,
  vmIdFragment: 'short' | 'multibase' = 'short'
): NormalizedVerificationMethods => {
  const all: NormalizedVerificationMethods = {
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    keyAgreement: [],
    capabilityDelegation: [],
    capabilityInvocation: [],
  };

  if (!verificationMethod || verificationMethod.length === 0) {
    return all;
  }

  // First collect all VMs. `purpose` is a creation-time directive for the
  // relationship wiring below, not a DID Core verification-method property, so
  // it is dropped from the emitted entries.
  const vms: VerificationMethod[] = verificationMethod.map(({ purpose, ...vm }) => ({
    ...vm,
    id: vm.id ?? createVMID(vm, did, vmIdFragment),
    // Default controller to the DID — required by W3C DID Core §5.2
    controller: vm.controller ?? did ?? undefined,
  }));
  all.verificationMethod = vms;

  // A VM's `purpose` may name a single relationship or several; an absent (or
  // empty) purpose defaults the key into authentication.
  const purposesOf = (vm: VerificationMethod): string[] =>
    vm.purpose == null ? [] : Array.isArray(vm.purpose) ? vm.purpose : [vm.purpose];
  const idOf = (vm: VerificationMethod) => vm.id ?? createVMID(vm, did, vmIdFragment);

  // Then handle relationships - default to authentication if no purpose is specified
  all.authentication = verificationMethod
    .filter((vm) => {
      const purposes = purposesOf(vm);
      return purposes.length === 0 || purposes.includes('authentication');
    })
    .map(idOf);

  all.assertionMethod = verificationMethod.filter((vm) => purposesOf(vm).includes('assertionMethod')).map(idOf);

  all.keyAgreement = verificationMethod.filter((vm) => purposesOf(vm).includes('keyAgreement')).map(idOf);

  all.capabilityDelegation = verificationMethod
    .filter((vm) => purposesOf(vm).includes('capabilityDelegation'))
    .map(idOf);

  all.capabilityInvocation = verificationMethod
    .filter((vm) => purposesOf(vm).includes('capabilityInvocation'))
    .map(idOf);

  return all;
};

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

export const findVerificationMethod = (doc: DIDDoc, vmId: string): VerificationMethod | null => {
  // Check in the verificationMethod array
  if (doc.verificationMethod?.some((vm) => vm.id === vmId)) {
    return doc.verificationMethod.find((vm) => vm.id === vmId) ?? null;
  }

  // Check in other verification method relationship arrays
  const vmRelationships = [
    'authentication',
    'assertionMethod',
    'keyAgreement',
    'capabilityInvocation',
    'capabilityDelegation',
  ];
  for (const relationship of vmRelationships) {
    const relationshipValues = doc[relationship as keyof DIDDoc];
    if (
      Array.isArray(relationshipValues) &&
      relationshipValues.some((item) => {
        if (typeof item !== 'object' || item === null) return false;
        const maybeId = (item as { id?: unknown }).id;
        return maybeId === vmId;
      })
    ) {
      const match = relationshipValues.find((item) => {
        if (typeof item !== 'object' || item === null) return false;
        const maybeId = (item as { id?: unknown }).id;
        return maybeId === vmId;
      });
      if (match && typeof match === 'object') {
        return match as VerificationMethod;
      }
    }
  }

  return null;
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

export function replaceValueInObject<T>(obj: T, searchValue: string, replaceValue: string): T {
  if (typeof obj === 'string') {
    return obj.replaceAll(searchValue, replaceValue) as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => replaceValueInObject(item, searchValue, replaceValue)) as T;
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = replaceValueInObject(value, searchValue, replaceValue);
    }
    return result as T;
  }
  return obj;
}
