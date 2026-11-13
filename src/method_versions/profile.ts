/**
 * Method profiles for the shared v1.0 log code.
 *
 * did:webvh and did:vh share one log format: the same entry layout, SCID and
 * entry-hash algorithms, key authorization, pre-rotation and witness rules.
 * They differ in the DID syntax and in a small set of rules. The log code in
 * this directory reads those differences from a {@link MethodProfile} and
 * imports no method-specific constant or parser itself.
 */
import { DIDResolutionError } from '@interop/data-integrity-core';
import { METHOD_PROTOCOL_V1_0, VH_METHOD_PROTOCOL_V1_0 } from '../constants.js';
import { parseDidWebvhIdentifier } from '../utils/did-identifier.js';
import { parseDidVhIdentifier } from '../utils/did-vh-identifier.js';

/** The parts of an entry's `state.id` the log code reads. */
export interface ParsedStateId {
  scid: string;
  /**
   * The location the DID names, compared between entries to detect a move.
   * Empty for a method whose DID carries no location.
   */
  locationKey: string;
  paths?: string[];
}

export interface MethodProfile {
  /** The `method` parameter value a log of this method declares. */
  method: string;
  /**
   * Parses and validates an entry's `state.id`. `allowScidPlaceholder`
   * accepts the `{SCID}` creation-template form.
   */
  parseStateId(id: string, context: string, options?: { allowScidPlaceholder?: boolean }): ParsedStateId;
  /**
   * Whether the DID names a location. Portability (the `portable` parameter
   * and the location options of create and update), moves and the parallel
   * `did:web` alias exist only for a method that has one.
   */
  hasLocation: boolean;
  /** Whether a JSON `null` parameter value is accepted as the parameter's default. */
  allowNullParameters: boolean;
  /** Whether `versionTime` must be in whole seconds. */
  wholeSecondVersionTime: boolean;
  /** Whether an entry that sets `updateKeys` to `[]` ends the log. */
  emptyUpdateKeysEndLog: boolean;
  /** Whether every entry must declare `nextKeyHashes` while pre-rotation is active. */
  prerotationRequiresNextKeyHashes: boolean;
  /**
   * The error thrown for a `method` value other than this profile's.
   * `versionNumber` is set when a later entry declares it, and absent for
   * the first entry.
   */
  unsupportedMethodError(method: unknown, versionNumber?: number): Error;
}

export const WEBVH_PROFILE: MethodProfile = {
  method: METHOD_PROTOCOL_V1_0,
  parseStateId: parseDidWebvhIdentifier,
  hasLocation: true,
  allowNullParameters: true,
  wholeSecondVersionTime: false,
  emptyUpdateKeysEndLog: false,
  prerotationRequiresNextKeyHashes: false,
  unsupportedMethodError: (method, versionNumber) =>
    versionNumber === undefined
      ? new Error(`'${method}' is not a supported method version.`)
      : new Error(
          `version '${versionNumber}' has unsupported or downgraded method '${method}'; ` +
            `expected '${METHOD_PROTOCOL_V1_0}'`
        ),
};

/** A well-formed did:vh `method` value: `did:vh:<major>.<minor>`, no leading zeros. */
const VH_METHOD_VALUE_PATTERN = /^did:vh:(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export const VH_PROFILE: MethodProfile = {
  method: VH_METHOD_PROTOCOL_V1_0,
  parseStateId: (id, context, options) => ({ scid: parseDidVhIdentifier(id, context, options), locationKey: '' }),
  hasLocation: false,
  allowNullParameters: false,
  wholeSecondVersionTime: true,
  emptyUpdateKeysEndLog: true,
  prerotationRequiresNextKeyHashes: true,
  // A well-formed value this library does not implement is an unsupported
  // feature. Anything else fails verification: another method's value, a
  // malformed one, or a later entry that lowers the version.
  unsupportedMethodError: (method, versionNumber) => {
    const message = `'${method}' is not a supported method version; expected '${VH_METHOD_PROTOCOL_V1_0}'`;
    const version = typeof method === 'string' ? VH_METHOD_VALUE_PATTERN.exec(method) : null;
    const lowersVersion = versionNumber !== undefined && version !== null && Number(version[1]) < 1;
    if (version === null || lowersVersion) {
      return new Error(message);
    }
    return new DIDResolutionError(message, { code: 'featureNotSupported' });
  },
};
