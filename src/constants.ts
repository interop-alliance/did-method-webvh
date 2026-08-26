export const PLACEHOLDER = '{SCID}';
export const DID_PLACEHOLDER = '{DID}';
export const METHOD = 'webvh';
export const BASE_CONTEXT = ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'];

// Version 1.0 method constants
export const METHOD_VERSION_1_0 = '1.0';
export const METHOD_PROTOCOL_V1_0 = `did:${METHOD}:${METHOD_VERSION_1_0}`;

// Spec default for the `ttl` DID parameter: cache lifetime in seconds when a
// log never sets one.
export const DEFAULT_TTL_SECONDS = 3600;

// Verification relationships
export const VERIFICATION_RELATIONSHIPS = [
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityDelegation',
  'capabilityInvocation',
] as const;

export type VerificationRelationship = (typeof VERIFICATION_RELATIONSHIPS)[number];
