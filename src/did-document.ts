import type { VerificationRelationship } from './constants.js';
import { BASE_CONTEXT, DID_PLACEHOLDER, PLACEHOLDER, VERIFICATION_RELATIONSHIPS } from './constants.js';
import type { DIDDoc, ServiceEndpoint, VerificationMethod } from './interfaces.js';
import { parseDidWebvhIdentifier } from './utils/did-identifier.js';
import { replaceValueInObject, replaceValuesInObject } from './utils/object.js';
import { requireDidDocumentId } from './utils.js';

type NormalizedVerificationMethods = Required<Pick<DIDDoc, 'verificationMethod' | VerificationRelationship>>;

export function validateCreateDidDocument(didDocument: DIDDoc): void {
  if (!didDocument || typeof didDocument !== 'object') {
    throw new Error('didDocument must be an object');
  }
  if (typeof didDocument.id !== 'string') {
    throw new Error("didDocument 'id' field must be a string");
  }
  if (!didDocument.id.includes(PLACEHOLDER) && !didDocument.id.includes(DID_PLACEHOLDER)) {
    throw new Error("didDocument.id must contain a '{SCID}' or '{DID}' placeholder");
  }
}

export function convertWebvhIdToWebId(id: string): string {
  let locationKey: string;
  try {
    ({ locationKey } = parseDidWebvhIdentifier(id, 'did:webvh id'));
  } catch {
    throw new Error(`Invalid did:webvh id '${id}'`);
  }
  return `did:web:${locationKey}`;
}

/**
 * Appends `alias` to an `alsoKnownAs` value (deduplicating), validating that
 * the existing value -- when present -- is an array. Shared by every
 * alias-appending path so the validation and dedup rules stay uniform.
 */
export function appendAlias(alsoKnownAs: string[] | undefined, alias: string): string[] {
  if (alsoKnownAs !== undefined && !Array.isArray(alsoKnownAs)) {
    throw new Error('alsoKnownAs is not an array');
  }

  const aliases = Array.isArray(alsoKnownAs) ? [...alsoKnownAs] : [];
  if (!aliases.includes(alias)) {
    aliases.push(alias);
  }
  return aliases;
}

export function enrichAlsoKnownAs(doc: DIDDoc, did: string, opts: { alsoKnownAsWeb?: boolean }): DIDDoc {
  if (doc.alsoKnownAs !== undefined && !Array.isArray(doc.alsoKnownAs)) {
    throw new Error('alsoKnownAs is not an array');
  }

  if (!opts.alsoKnownAsWeb) {
    return doc;
  }

  return {
    ...doc,
    alsoKnownAs: appendAlias(doc.alsoKnownAs, convertWebvhIdToWebId(did)),
  };
}

// Safety guard: Strip secret keys from verification methods before creating DID document
export function sanitizeVerificationMethods(
  verificationMethods?: VerificationMethod[]
): VerificationMethod[] | undefined {
  return verificationMethods?.map((vm) => {
    if (vm.secretKeyMultibase) {
      console.warn(
        'Warning: Removing secretKeyMultibase from verification method - secret keys should not be stored in DID documents'
      );
      const { secretKeyMultibase, ...safeVm } = vm;
      return safeVm;
    }
    return vm;
  });
}

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

  // First collect all VMs, materializing a stable id for each. `purpose` is a
  // creation-time directive for the relationship wiring below, not a DID Core
  // verification-method property, so it is dropped from the emitted entries. The
  // materialized id is retained alongside the purpose so relationship entries
  // reference the exact id emitted into `verificationMethod` rather than
  // re-deriving it (a re-derivation would allocate a fresh random fragment for a
  // VM that carries neither an `id` nor a `publicKeyMultibase`).
  const materialized = verificationMethod.map((source) => {
    const { purpose, ...vm } = source;
    const id = vm.id ?? createVMID(vm, did, vmIdFragment);
    return {
      purpose,
      vm: {
        ...vm,
        id,
        // Default controller to the DID -- required by W3C DID Core §5.2
        controller: vm.controller ?? did ?? undefined,
      },
    };
  });
  all.verificationMethod = materialized.map((entry) => entry.vm);

  // A VM's `purpose` may name a single relationship or several; an absent (or
  // empty) purpose defaults the key into authentication. One pass over the
  // materialized VMs wires all five relationship arrays. A repeated
  // relationship in one VM's purpose list emits its id once -- a duplicate
  // reference would be an invalid document (and a different SCID for the same
  // input).
  for (const entry of materialized) {
    const purposes = entry.purpose == null ? [] : Array.isArray(entry.purpose) ? entry.purpose : [entry.purpose];
    const targets = purposes.length === 0 ? ['authentication' as const] : purposes;
    for (const target of new Set(targets)) {
      if ((VERIFICATION_RELATIONSHIPS as readonly string[]).includes(target)) {
        all[target as VerificationRelationship].push(entry.vm.id);
      }
    }
  }

  return all;
};

/**
 * Predicate factory matching any object node carrying `id === vmId`. Shared by
 * {@link findVerificationMethod} and the did-io driver's fragment dereference.
 */
export const hasMatchingId =
  (vmId: string) =>
  (item: unknown): item is VerificationMethod => {
    if (typeof item !== 'object' || item === null) return false;
    return (item as { id?: unknown }).id === vmId;
  };

export const findVerificationMethod = (doc: DIDDoc, vmId: string): VerificationMethod | null => {
  const matchesId = hasMatchingId(vmId);

  // Check in the verificationMethod array
  const directMatch = doc.verificationMethod?.find(matchesId);
  if (directMatch) {
    return directMatch;
  }

  // Check in other verification method relationship arrays
  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const relationshipValues = doc[relationship as keyof DIDDoc];
    if (Array.isArray(relationshipValues)) {
      const match = relationshipValues.find(matchesId);
      if (match) {
        return match;
      }
    }
  }

  return null;
};

export const createDIDDoc = (options: {
  did: string;
  verificationMethods?: VerificationMethod[];
  vmIdFragment?: 'short' | 'multibase';
  context?: string | string[] | object | object[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityDelegation?: string[];
  capabilityInvocation?: string[];
  alsoKnownAs?: string[];
  services?: ServiceEndpoint[];
}): DIDDoc => {
  const { did } = options;
  const all = normalizeVMs(options.verificationMethods, did, options.vmIdFragment);
  const derivedProperties = ['verificationMethod', ...VERIFICATION_RELATIONSHIPS] as const;
  const directProperties = [...VERIFICATION_RELATIONSHIPS, 'alsoKnownAs'] as const;
  const assignIfPresent = <K extends keyof DIDDoc>(property: K, value: DIDDoc[K] | undefined) => {
    // Omit empty verification-relationship arrays rather than emitting `[]`.
    if (Array.isArray(value) && value.length === 0) {
      return;
    }

    if (value) {
      doc[property] = value;
    }
  };

  // Create the base document
  const doc: DIDDoc = {
    '@context': options.context || BASE_CONTEXT,
    id: did,
    controller: did,
  };

  // Add verification methods and relationships from normalizeVMs
  if (all && typeof all === 'object') {
    for (const property of derivedProperties) {
      assignIfPresent(property, all[property]);
    }
  }

  // Add direct properties from options
  for (const property of directProperties) {
    assignIfPresent(property, options[property]);
  }

  if (options.services) {
    doc.service = options.services;
  }

  return doc;
};

export function replaceCreateDidPlaceholders<T>(input: T, scid: string, did: string): T {
  return replaceValuesInObject(input, [
    [PLACEHOLDER, scid],
    [DID_PLACEHOLDER, did],
  ]);
}

export function generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc {
  const { scid } = parseDidWebvhIdentifier(didwebvhDid, 'did:webvh id');
  const webDoc = replaceValueInObject(didwebvhDoc, `did:webvh:${scid}:`, 'did:web:');

  const webDid = requireDidDocumentId(webDoc.id);
  const aliases = appendAlias(
    (Array.isArray(webDoc.alsoKnownAs) ? webDoc.alsoKnownAs : []).filter((alias: string) => alias !== webDid),
    didwebvhDid
  );

  return {
    ...webDoc,
    alsoKnownAs: [...new Set(aliases)],
  };
}
