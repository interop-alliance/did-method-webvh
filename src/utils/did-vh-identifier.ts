/**
 * did:vh identifier grammar: `did:vh:<scid>`.
 *
 * A did:vh DID carries no location, so there is no URL derivation here. The
 * SCID grammar is the one did:webvh uses.
 */
import { PLACEHOLDER as SCID_PLACEHOLDER, VH_METHOD } from '../constants.js';
import { SCID_PATTERN } from './did-identifier.js';

const DID_PREFIX = `did:${VH_METHOD}:`;

/**
 * Parses a `did:vh:<scid>` identifier and returns its SCID. The SCID is 46
 * base58btc characters, and nothing may follow it. `allowScidPlaceholder`
 * accepts the `{SCID}` creation-template form in place of a real SCID.
 *
 * @param did {string} The identifier to parse.
 * @param context {string} What the identifier is, for the error message.
 * @param [options.allowScidPlaceholder] {boolean} Accept `did:vh:{SCID}`.
 * @returns {string} The SCID (or the `{SCID}` placeholder).
 */
export function parseDidVhIdentifier(
  did: string,
  context: string,
  { allowScidPlaceholder = false }: { allowScidPlaceholder?: boolean } = {}
): string {
  if (typeof did !== 'string' || !did.startsWith(DID_PREFIX)) {
    throw new Error(`${context} must be a valid did:vh identifier`);
  }
  const scid = did.slice(DID_PREFIX.length);
  if (!SCID_PATTERN.test(scid) && !(allowScidPlaceholder && scid === SCID_PLACEHOLDER)) {
    throw new Error(`${context} must be 'did:vh:' followed by a SCID of 46 base58btc characters`);
  }
  return scid;
}
