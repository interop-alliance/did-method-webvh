import type { DIDLog, ParsedDidKeyVerificationMethod, WitnessProofFileEntry } from './interfaces.js';
import { getFileUrl } from './utils/did-identifier.js';
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
    return readLogFromString(text);
  } catch (error) {
    console.error('Error fetching DID log:', error);
    throw error;
  }
}

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
export { replaceValueInObject } from './utils/object.js';
