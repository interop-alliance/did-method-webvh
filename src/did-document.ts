import type { VerificationRelationship } from './constants.js';
import { BASE_CONTEXT, DID_PLACEHOLDER, PLACEHOLDER, VERIFICATION_RELATIONSHIPS } from './constants.js';
import type { DIDDoc, ServiceEndpoint, VerificationMethod } from './interfaces.js';
import { parseDidWebvhIdentifier } from './utils/did-identifier.js';
import { mapStringsInObject, replaceValueInObject, replaceValuesInObject } from './utils/object.js';
import { requireDidDocumentId } from './utils.js';

type NormalizedVerificationMethods = Required<Pick<DIDDoc, 'verificationMethod' | VerificationRelationship>>;

/**
 * Requires an authored `didDocument` to carry a non-empty string `id`, and
 * returns it. Shared by the create path (which goes on to require a
 * placeholder in it) and the update path (which goes on to require it to name
 * the DID being updated), so the two state the rule once.
 */
export function requireAuthoredDocumentId(didDocument: DIDDoc): string {
  if (typeof didDocument.id !== 'string' || didDocument.id.trim() === '') {
    throw new Error("didDocument 'id' field must be a string");
  }
  return didDocument.id;
}

export function validateCreateDidDocument(didDocument: DIDDoc): void {
  if (!didDocument || typeof didDocument !== 'object') {
    throw new Error('didDocument must be an object');
  }
  const id = requireAuthoredDocumentId(didDocument);
  if (!id.includes(PLACEHOLDER) && !id.includes(DID_PLACEHOLDER)) {
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

/**
 * Safety guard: rejects private key material before it can reach a DID
 * document. Walks `value` (including any nested objects and arrays, such as a
 * `ConditionalProof2022` `conditionOr` list) and throws if any property named
 * `secretKeyMultibase` is present -- nested material counts, since a
 * verification method type that carries its keys one level down would
 * otherwise be spread into the document untouched by `normalizeVMs`. `path`
 * names the root for the error message.
 */
export function assertNoPrivateKeyMaterial(value: unknown, path: string): void {
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      assertNoPrivateKeyMaterial(item, `${path}[${index}]`);
    }
    return;
  }
  if (typeof value !== 'object' || value === null) {
    return;
  }

  for (const [property, nestedValue] of Object.entries(value)) {
    const propertyPath = `${path}.${property}`;
    if (property === 'secretKeyMultibase' && nestedValue !== undefined) {
      throw new Error(
        `${propertyPath} contains private key material; private key material must not be included in DID documents`
      );
    }
    assertNoPrivateKeyMaterial(nestedValue, propertyPath);
  }
}

/**
 * Requires every authored verification method to carry a non-empty `id` and an
 * explicit `controller`. A caller-authored `didDocument` bypasses
 * {@link normalizeVMs}, which is what would otherwise synthesize a fragment via
 * {@link createVMID} and default the controller to the subject DID, so an
 * authored document has to supply both itself.
 */
export function assertValidAuthoredVerificationMethods(didDocument: DIDDoc): void {
  const assertValid = (vm: unknown, location: string): void => {
    if (typeof vm !== 'object' || vm === null) {
      return;
    }
    const candidate = vm as Record<string, unknown>;
    if (typeof candidate.id !== 'string' || candidate.id.trim() === '') {
      throw new Error(`Verification method at ${location} must have a non-empty string 'id'`);
    }
    if (typeof candidate.controller !== 'string' || candidate.controller.trim() === '') {
      throw new Error(`Verification method at ${location} must have an explicit string 'controller'`);
    }
  };

  didDocument.verificationMethod?.forEach((vm, index) => {
    assertValid(vm, `verificationMethod[${index}]`);
  });

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const entries: unknown = didDocument[relationship];
    if (!Array.isArray(entries)) {
      continue;
    }
    // Relationship entries are normally id references; an object entry is an
    // embedded verification method and gets the same treatment.
    entries.forEach((entry, index) => {
      if (typeof entry === 'object' && entry !== null) {
        assertValid(entry, `${relationship}[${index}]`);
      }
    });
  }
}

/**
 * Rewrites references to `fromDid` so they point at `toDid`, for a DID document
 * carried forward across a portable move. Covers the document `controller`
 * (string or array), the `id` and `controller` of every verification method --
 * whether listed under `verificationMethod`, embedded in a verification
 * relationship, or referenced from one by id -- and every string inside the
 * `service` array, so a service `id` or a `serviceEndpoint` naming the moved
 * DID follows it. References to any other DID are left untouched.
 */
export function rewriteSelfReferences(doc: DIDDoc, fromDid: string, toDid: string): DIDDoc {
  const rewriteDid = (value: string): string => (value === fromDid ? toDid : value);
  // A self reference is the bare DID or a DID URL built on it -- the DID
  // followed by a fragment, path, or query. A longer DID that merely starts
  // with `fromDid` (the next character is `:`) is a different DID.
  const rewriteReference = (value: string): string => {
    if (value === fromDid) {
      return toDid;
    }
    const separator = value.charAt(fromDid.length);
    if (value.startsWith(fromDid) && (separator === '#' || separator === '/' || separator === '?')) {
      return `${toDid}${value.slice(fromDid.length)}`;
    }
    return value;
  };
  const rewriteEmbedded = (vm: Record<string, unknown>): Record<string, unknown> => {
    const updated = { ...vm };
    if (typeof updated.id === 'string') {
      updated.id = rewriteReference(updated.id);
    }
    if (typeof updated.controller === 'string') {
      updated.controller = rewriteDid(updated.controller);
    }
    return updated;
  };

  const rewritten: DIDDoc = { ...doc };

  if (typeof doc.controller === 'string') {
    rewritten.controller = rewriteDid(doc.controller);
  } else if (Array.isArray(doc.controller)) {
    rewritten.controller = doc.controller.map(rewriteDid);
  }

  // A service entry holds free-form JSON, so every string in it is a candidate.
  if (Array.isArray(doc.service)) {
    rewritten.service = doc.service.map((service) => mapStringsInObject(service, rewriteReference));
  }

  if (Array.isArray(doc.verificationMethod)) {
    rewritten.verificationMethod = doc.verificationMethod.map(
      (vm) => rewriteEmbedded(vm as unknown as Record<string, unknown>) as unknown as VerificationMethod
    );
  }

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const entries: unknown = doc[relationship];
    if (!Array.isArray(entries)) {
      continue;
    }
    // `DIDDoc` declares relationships as `string[]`; embedded verification
    // methods are legal in a caller-authored document, so they are handled at
    // runtime and cast back at this one boundary.
    rewritten[relationship] = entries.map((entry) => {
      if (typeof entry === 'string') {
        return rewriteReference(entry);
      }
      if (typeof entry === 'object' && entry !== null) {
        return rewriteEmbedded(entry as Record<string, unknown>);
      }
      return entry;
    }) as string[];
  }

  return rewritten;
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

/**
 * Refuses the mutually exclusive context options. `context` replaces the
 * document's `@context` wholesale, `additionalContext` appends to it; passing
 * both is a caller bug rather than a resolvable combination.
 *
 * @param options {object}
 * @param [options.context] {string | string[] | object | object[]}
 * @param [options.additionalContext] {(string | object)[]}
 */
export function assertContextOptions(options: {
  context?: string | string[] | object | object[];
  additionalContext?: (string | object)[];
}): void {
  if (options.context !== undefined && options.additionalContext !== undefined) {
    throw new Error("Pass either 'context' (full override) or 'additionalContext' (append), not both");
  }
}

function contextEntriesEqual(present: unknown, candidate: string | object): boolean {
  if (typeof present === 'string' || typeof candidate === 'string') {
    return present === candidate;
  }
  return JSON.stringify(present) === JSON.stringify(candidate);
}

/**
 * Appends `additionalContext` entries onto a base `@context` value, skipping
 * entries already present. String entries compare by value; object entries
 * compare by their JSON serialization, so two equivalent objects written with
 * different key order are treated as distinct.
 *
 * An absent base resolves to `BASE_CONTEXT`; an absent or empty
 * `additionalContext` returns the base value unchanged (array or not).
 *
 * @param base {string | string[] | object | object[] | undefined}
 * @param [additionalContext] {(string | object)[]}
 * @returns {string | string[] | object | object[]}
 */
/**
 * Validates a caller-authored `didDocument` and returns the owned clone that
 * entry preparation goes on to work with. `additionalContext` is the only
 * overlay applied here -- it appends to whatever `@context` the authored
 * document carries; every other document-shaping option is refused alongside
 * `didDocument`. Shared by the create and update paths so the guards and the
 * merge order stay in step.
 */
export function prepareAuthoredDocument(didDocument: DIDDoc, additionalContext?: (string | object)[]): DIDDoc {
  assertNoPrivateKeyMaterial(didDocument, 'didDocument');
  assertValidAuthoredVerificationMethods(didDocument);

  const doc = structuredClone(didDocument);
  if (additionalContext !== undefined) {
    doc['@context'] = mergeAdditionalContext(doc['@context'], additionalContext);
  }
  return doc;
}

export function mergeAdditionalContext(
  base: string | string[] | object | object[] | undefined,
  additionalContext?: (string | object)[]
): string | string[] | object | object[] {
  const resolvedBase = base ?? BASE_CONTEXT;
  if (!additionalContext || additionalContext.length === 0) {
    return resolvedBase;
  }

  const merged: (string | object)[] = Array.isArray(resolvedBase) ? [...resolvedBase] : [resolvedBase];
  for (const entry of additionalContext) {
    if (!merged.some((present) => contextEntriesEqual(present, entry))) {
      merged.push(entry);
    }
  }

  return merged as string[] | object[];
}

export const createDIDDoc = (options: {
  did: string;
  verificationMethods?: VerificationMethod[];
  vmIdFragment?: 'short' | 'multibase';
  context?: string | string[] | object | object[];
  additionalContext?: (string | object)[];
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
    '@context': mergeAdditionalContext(options.context || BASE_CONTEXT, options.additionalContext),
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
