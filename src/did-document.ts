import type { VerificationRelationship } from './constants.js';
import { BASE_CONTEXT, DID_PLACEHOLDER, PLACEHOLDER, VERIFICATION_RELATIONSHIPS } from './constants.js';
import type { DIDDoc, ServiceEndpoint, VerificationMethod } from './interfaces.js';
import { replaceValueInObject } from './utils/object.js';

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
  // empty) purpose defaults the key into authentication.
  const purposesOf = (purpose: VerificationMethod['purpose']): string[] =>
    purpose == null ? [] : Array.isArray(purpose) ? purpose : [purpose];

  // Then handle relationships - default to authentication if no purpose is specified
  all.authentication = materialized
    .filter((entry) => {
      const purposes = purposesOf(entry.purpose);
      return purposes.length === 0 || purposes.includes('authentication');
    })
    .map((entry) => entry.vm.id);

  all.assertionMethod = materialized
    .filter((entry) => purposesOf(entry.purpose).includes('assertionMethod'))
    .map((entry) => entry.vm.id);

  all.keyAgreement = materialized
    .filter((entry) => purposesOf(entry.purpose).includes('keyAgreement'))
    .map((entry) => entry.vm.id);

  all.capabilityDelegation = materialized
    .filter((entry) => purposesOf(entry.purpose).includes('capabilityDelegation'))
    .map((entry) => entry.vm.id);

  all.capabilityInvocation = materialized
    .filter((entry) => purposesOf(entry.purpose).includes('capabilityInvocation'))
    .map((entry) => entry.vm.id);

  return all;
};

export const findVerificationMethod = (doc: DIDDoc, vmId: string): VerificationMethod | null => {
  // Check in the verificationMethod array
  const directMatch = doc.verificationMethod?.find((vm) => vm.id === vmId);
  if (directMatch) {
    return directMatch;
  }

  // Check in other verification method relationship arrays
  const hasMatchingId = (item: unknown): item is VerificationMethod => {
    if (typeof item !== 'object' || item === null) return false;
    return (item as { id?: unknown }).id === vmId;
  };

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const relationshipValues = doc[relationship as keyof DIDDoc];
    if (Array.isArray(relationshipValues)) {
      const match = relationshipValues.find(hasMatchingId);
      if (match) {
        return match;
      }
    }
  }

  return null;
};

export const createDIDDoc = async (options: {
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
}): Promise<{ doc: DIDDoc }> => {
  const { did } = options;
  const all = normalizeVMs(options.verificationMethods, did, options.vmIdFragment);
  const derivedProperties = ['verificationMethod', ...VERIFICATION_RELATIONSHIPS] as const;
  const directProperties = [
    'authentication',
    'assertionMethod',
    'keyAgreement',
    'capabilityDelegation',
    'capabilityInvocation',
    'alsoKnownAs',
  ] as const;
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

  return { doc };
};

export function replaceCreateDidPlaceholders<T>(input: T, scid: string, did: string): T {
  const withScid = replaceValueInObject(input, PLACEHOLDER, scid);
  return replaceValueInObject(withScid, DID_PLACEHOLDER, did) as T;
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
