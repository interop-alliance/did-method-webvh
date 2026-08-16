export { hashChainIsValid, scidIsFromHash, verifyEntryProofs } from './assertions.js';
export { BASE_CONTEXT, DID_PLACEHOLDER, PLACEHOLDER as SCID_PLACEHOLDER } from './constants.js';
export {
  AbstractCrypto,
  createDataIntegrityProofTemplate,
  createDocumentSigner,
  prepareDataForSigning,
  signDataIntegrityProof,
  signerFromExternalKey,
} from './cryptography.js';
export { convertWebvhIdToWebId, createVMID, generateParallelDidWeb } from './did-document.js';
export * from './interfaces.js';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method.js';
export { WitnessThresholdError } from './method_versions/method.v1.0.resolution.js';
export type { ResolutionOptionsError, WebvhDocumentMetadata } from './resolver-result.js';
export {
  mapErrorToCode,
  toErrorMeta,
  toErrorResult,
  toResolutionResult,
  validateResolutionSelectors,
  validateSingleVersionSelector,
  WEBVH_ERROR_TYPES,
} from './resolver-result.js';
export { canonicalizeStrict } from './utils/canonicalize.js';
export { deriveHash, deriveNextKeyHash } from './utils/crypto.js';
export { MultibaseEncoding, multibaseDecode, multibaseEncode } from './utils/multiformats.js';
export {
  buildVersionId,
  getBaseUrl,
  getFileUrl,
  logToJsonlString,
  parseAndValidateVersionId,
  parseDidKeyDid,
  parseDidKeyVerificationMethod,
  parseDidWebvhIdentifier,
  readLogFromString,
} from './utils.js';
export { defaultWebvhLogVerifier } from './verifier.js';
export { createResolveVM, resolveVM } from './vm-resolver.js';
export {
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from './witness.js';
