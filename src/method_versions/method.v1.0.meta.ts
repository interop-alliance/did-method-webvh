/**
 * Shared parameter-derived state helpers for the v1.0 method implementation,
 * used by both the write path (create/update/deactivate) and the resolver.
 */
import { DEFAULT_TTL_SECONDS } from '../constants.js';
import type { DIDLogEntry, DIDResolutionMeta } from '../interfaces.js';
import { resolveWitnessParameter } from '../witness.js';

/**
 * Spec invariant: pre-rotation is active exactly when the governing
 * `nextKeyHashes` list is non-empty.
 */
export const hasPrerotation = (nextKeyHashes: string[] | undefined | null): boolean => {
  return (nextKeyHashes?.length ?? 0) > 0;
};

/** Genesis parameters after validation: the fields the spec requires. */
export interface GenesisParameters {
  scid: string;
  updateKeys: string[];
}

/**
 * Validating parse of a genesis entry's required parameters. Rejects a log
 * whose first entry is missing `scid` or `updateKeys` instead of letting
 * `undefined` flow into resolution meta.
 */
export const parseGenesisParameters = (parameters: DIDLogEntry['parameters']): GenesisParameters => {
  const { scid, updateKeys } = parameters;
  if (typeof scid !== 'string' || scid.length === 0) {
    throw new Error(`version '1' must declare a non-empty scid parameter`);
  }
  if (!Array.isArray(updateKeys) || updateKeys.length === 0) {
    throw new Error(`version '1' must declare a non-empty updateKeys parameter`);
  }
  return { scid, updateKeys };
};

/**
 * Folds one log entry's parameters into resolution meta -- the single reducer
 * shared by the resolver loop and the create/update/deactivate result
 * builders, so both paths report identical state for the same log. A genesis
 * entry (no `previousMeta`) seeds every field, enforcing the
 * {@link parseGenesisParameters} invariant; subsequent entries inherit absent
 * parameters from the previous meta. All other validation (portability,
 * pre-rotation, witness rules) stays with the resolver. Parameter arrays and
 * the witness object are copied so meta never aliases the entry: mutating one
 * cannot corrupt the other.
 */
export const applyEntryToMeta = (entry: DIDLogEntry, previousMeta?: DIDResolutionMeta): DIDResolutionMeta => {
  const { parameters } = entry;
  const copyWatchers = (watchers: string[] | null | undefined): string[] | null =>
    watchers == null ? null : [...watchers];

  if (!previousMeta) {
    const { scid, updateKeys } = parseGenesisParameters(parameters);
    const nextKeyHashes = [...(parameters.nextKeyHashes ?? [])];
    return {
      versionId: entry.versionId,
      versionTime: entry.versionTime,
      created: entry.versionTime,
      updated: entry.versionTime,
      scid,
      updateKeys: [...updateKeys],
      portable: parameters.portable ?? false,
      ttl: parameters.ttl ?? DEFAULT_TTL_SECONDS,
      nextKeyHashes,
      prerotation: hasPrerotation(nextKeyHashes),
      witness: resolveWitnessParameter(parameters),
      watchers: copyWatchers(parameters.watchers),
      deactivated: parameters.deactivated ?? false,
    };
  }

  const nextKeyHashes =
    'nextKeyHashes' in parameters ? [...(parameters.nextKeyHashes ?? [])] : previousMeta.nextKeyHashes;
  return {
    ...previousMeta,
    versionId: entry.versionId,
    versionTime: entry.versionTime,
    updated: entry.versionTime,
    updateKeys: 'updateKeys' in parameters ? [...(parameters.updateKeys ?? [])] : previousMeta.updateKeys,
    // portable can only be locked off after the first entry, never (re)enabled.
    portable: parameters.portable === false ? false : previousMeta.portable,
    ttl: 'ttl' in parameters ? (parameters.ttl ?? DEFAULT_TTL_SECONDS) : previousMeta.ttl,
    nextKeyHashes,
    prerotation: hasPrerotation(nextKeyHashes),
    witness: resolveWitnessParameter(parameters) ?? previousMeta.witness,
    watchers: 'watchers' in parameters ? copyWatchers(parameters.watchers) : previousMeta.watchers,
    deactivated: previousMeta.deactivated || parameters.deactivated === true,
  };
};
