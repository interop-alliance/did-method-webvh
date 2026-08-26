import type { IProblemDetails } from '@interop/data-integrity-core';

export type DataIntegrityProofPurpose =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export type DataIntegrityProofType = 'DataIntegrityProof';
export type DataIntegrityCryptosuite = 'eddsa-jcs-2022';

export interface DataIntegrityProofTemplate {
  id?: string;
  type: DataIntegrityProofType;
  cryptosuite: DataIntegrityCryptosuite;
  verificationMethod: string;
  created: string;
  proofPurpose: DataIntegrityProofPurpose;
}

export type SignableDocument = DIDLogEntry | DIDDoc | Pick<DIDLogEntry, 'versionId'>;

export interface SigningInput<TDocument = SignableDocument> {
  document: TDocument;
  proof: DataIntegrityProofTemplate;
}

export interface SigningOutput {
  proofValue: string;
}

export interface Signer<TDocument = SignableDocument> {
  sign(input: SigningInput<TDocument>): Promise<SigningOutput>;
  getVerificationMethodId(): string;
}

export interface Verifier {
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
}

/**
 * Resolves a proof's `verificationMethod` id to its key material. The default
 * implementation handles `did:key` and `did:webvh`; injectable for other
 * schemes or for offline verification.
 */
export type ResolveVerificationMethod = (
  verificationMethod: string
) => Promise<{ publicKeyMultibase?: string } | null | undefined>;

export interface SignerOptions {
  verificationMethod?: VerificationMethod | null;
  useStaticId?: boolean;
}

/**
 * RFC 9457 problem details for a resolution failure; the shared shape from
 * `@interop/data-integrity-core` (`IProblemDetails`), re-exported under this
 * package's historical name.
 */
export type ProblemDetails = IProblemDetails;

/**
 * Codes surfaced on `didResolutionMetadata.error` -- the subset of the shared
 * `IDIDResolutionErrorCode` vocabulary this method emits.
 *
 * `invalidDid`/`notFound` match DID Core section 7.1.2; `invalidDidUrl` is
 * reserved for a DID URL that violates `did-url` syntax (e.g. malformed
 * percent-encoding); `invalidOptions` covers well-formed URLs carrying invalid
 * resolution options (conflicting or ill-typed version selectors) per the DID
 * Resolution spec's INVALID_OPTIONS; `internalError` covers
 * transport/resolver-side failures.
 */
export type DidResolutionError = 'invalidDid' | 'invalidDidUrl' | 'invalidOptions' | 'notFound' | 'internalError';

export interface DIDResolutionMeta {
  versionId: string;
  versionTime: string;
  created: string;
  updated: string;
  updateKeys: string[];
  scid: string;
  prerotation: boolean;
  portable: boolean;
  /** Cache lifetime in seconds; the spec default (3600) when the log never sets `ttl`. */
  ttl: number;
  nextKeyHashes: string[];
  deactivated: boolean;
  witness?: WitnessParameter;
  watchers?: string[] | null;
  error?: DidResolutionError;
  problemDetails?: ProblemDetails;
}

export interface DIDDoc {
  '@context'?: string | string[] | object | object[];
  id?: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityInvocation?: string[];
  capabilityDelegation?: string[];
  verificationMethod?: VerificationMethod[];
  service?: ServiceEndpoint[];
}

export interface VerificationMethod {
  id?: string;
  type: string;
  controller?: string;
  publicKeyMultibase?: string;
  secretKeyMultibase?: string;
  // A single verification relationship, or several -- the key is referenced by
  // id from each listed relationship. Absent (or empty) defaults to
  // authentication.
  purpose?: DataIntegrityProofPurpose | DataIntegrityProofPurpose[];
  publicKeyJwk?: JsonObject;
  use?: string;
}

export interface WitnessEntry {
  id: string; // did:key DID
}

export interface ParsedDidKeyVerificationMethod {
  did: string;
  fragment?: string;
  keyMultibase: string;
}

export interface WitnessSigningOptions {
  versionId: string;
  witnesses: WitnessEntry[];
  witnessSignersByDid: Record<string, Signer>;
  created?: string;
}

export interface WitnessSigningResult {
  versionId: string;
  proof: DataIntegrityProof[];
}

export interface WitnessParameter {
  threshold?: number;
  witnesses?: WitnessEntry[];
}

export interface DataIntegrityProof {
  id?: string;
  type: DataIntegrityProofType;
  cryptosuite: DataIntegrityCryptosuite;
  verificationMethod: string;
  created: string;
  proofValue: string;
  proofPurpose: DataIntegrityProofPurpose;
}

export interface DIDLogEntry {
  versionId: string;
  versionTime: string;
  parameters: {
    method?: string;
    scid?: string;
    updateKeys?: string[];
    nextKeyHashes?: string[];
    portable?: boolean;
    witness?: WitnessParameter;
    watchers?: string[] | null;
    ttl?: number | null;
    deactivated?: boolean;
  };
  state: DIDDoc;
  proof?: DataIntegrityProof[];
}

export type DIDLog = DIDLogEntry[];

export interface ServiceEndpoint {
  id?: string;
  type: string | string[];
  serviceEndpoint?: string | string[] | JsonValue;
  [key: string]: unknown;
}

/** Result of a successful write operation (create/update): the DID, its document, meta, and the full log. */
export interface DIDOperationResult {
  did: string;
  doc: DIDDoc;
  meta: DIDResolutionMeta;
  log: DIDLog;
  webDoc?: DIDDoc;
}

export type CreateDIDResult = DIDOperationResult;

export type UpdateDIDResult = DIDOperationResult;

export interface CreateDIDInterface {
  /** Method spec version to create under; only `did:webvh:1.0` is supported. */
  method?: string;
  address?: string;
  signer: Signer;
  updateKeys: string[];
  verificationMethods?: VerificationMethod[];
  // How to derive verification-method id fragments from `publicKeyMultibase`:
  // 'short' (default) uses the last 8 chars; 'multibase' uses the full
  // multibase for a self-describing `#<publicKeyMultibase>` fragment.
  vmIdFragment?: 'short' | 'multibase';
  didDocument?: DIDDoc;
  services?: ServiceEndpoint[];
  paths?: string[];
  /**
   * Replaces the created document's `@context` wholesale; when unset the
   * document gets `BASE_CONTEXT`. Mutually exclusive with
   * `additionalContext` -- passing both throws.
   */
  context?: string | string[] | object | object[];
  /**
   * Context entries appended after `BASE_CONTEXT` (or, when `didDocument` is
   * supplied, after that document's own `@context`, falling back to
   * `BASE_CONTEXT` when it has none), deduplicated: a string entry already
   * present is skipped, and an object entry is skipped when its JSON
   * serialization matches an entry already present. Mutually exclusive with
   * `context` -- passing both throws.
   */
  additionalContext?: (string | object)[];
  alsoKnownAs?: string[];
  alsoKnownAsWeb?: boolean;
  portable?: boolean;
  nextKeyHashes?: string[];
  witness?: WitnessParameter | null;
  watchers?: string[] | null;
  created?: string;
  verifier?: Verifier;
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityDelegation?: string[];
  capabilityInvocation?: string[];
  /**
   * Re-verify the freshly signed entry before returning (default true). Can be
   * disabled to halve the signing-path crypto cost when the signer is trusted.
   */
  selfVerify?: boolean;
}

export interface UpdateDIDInterface {
  log: DIDLog;
  signer: Signer;
  services?: ServiceEndpoint[];
  /** New canonical address when moving a portable DID. */
  address?: string;
  paths?: string[];
  /** Append the parallel `did:web` alias and return its `webDoc`. */
  alsoKnownAsWeb?: boolean;
  /**
   * Optional explicit timestamp for the new DID log entry.
   *
   * When omitted, the implementation generates the timestamp internally.
   * This option is primarily intended for deterministic test/migration flows.
   */
  updated?: string;
  updateKeys?: string[];
  verificationMethods?: VerificationMethod[];
  // See CreateDIDInterface.vmIdFragment.
  vmIdFragment?: 'short' | 'multibase';
  /**
   * Replaces the updated document's `@context` wholesale. When unset, the
   * prior entry's `@context` is carried forward, falling back to
   * `BASE_CONTEXT` only when the prior document had none. Mutually exclusive
   * with `additionalContext` -- passing both throws.
   */
  context?: string | string[] | object | object[];
  /**
   * Context entries appended after the carried-forward `@context`,
   * deduplicated: a string entry already present is skipped, and an object
   * entry is skipped when its JSON serialization matches an entry already
   * present. Mutually exclusive with `context` -- passing both throws.
   */
  additionalContext?: (string | object)[];
  alsoKnownAs?: string[];
  portable?: boolean;
  nextKeyHashes?: string[];
  witness?: WitnessParameter | null;
  watchers?: string[] | null;
  verifier?: Verifier;
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityDelegation?: string[];
  capabilityInvocation?: string[];
  witnessProofs?: WitnessProofFileEntry[];
  /** See {@link CreateDIDInterface.selfVerify}. */
  selfVerify?: boolean;
  /**
   * Trusted resolution meta for the supplied log's last entry. When provided,
   * the operation skips re-resolving (and re-verifying) the whole log and
   * folds the new entry onto this state instead -- opt-in for callers that
   * just resolved or created the log themselves.
   */
  priorMeta?: DIDResolutionMeta;
}

export interface DeactivateDIDInterface {
  log: DIDLog;
  signer: Signer;
  verifier?: Verifier;
  updateKeys?: string[];
  /** See {@link CreateDIDInterface.selfVerify}. */
  selfVerify?: boolean;
  /** See {@link UpdateDIDInterface.priorMeta}. */
  priorMeta?: DIDResolutionMeta;
}

export interface ResolutionOptions {
  versionNumber?: number;
  versionId?: string;
  versionTime?: Date;
  verificationMethod?: string;
  verifier?: Verifier;
  /** Verification-method resolver for proof verification; defaults to the built-in did:key / did:webvh resolver. */
  resolveVM?: ResolveVerificationMethod;
  scid?: string;
  requestedDid?: string;
  /** Out-of-band witness proofs; when absent they are fetched from the DID's `did-witness.json`. */
  witnessProofs?: WitnessProofFileEntry[];
}

export interface WitnessProofFileEntry {
  versionId: string;
  proof: DataIntegrityProof[];
}
