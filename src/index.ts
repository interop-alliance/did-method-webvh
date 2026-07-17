export { PLACEHOLDER as SCID_PLACEHOLDER } from './constants.js';
export {
  AbstractCrypto,
  createDocumentSigner,
  createProof,
  prepareDataForSigning,
  signerFromExternalKey,
} from './cryptography.js';
export * from './interfaces.js';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method.js';
export type { ResolutionOptionsError, WebvhDocumentMetadata } from './resolver-result.js';
export {
  mapErrorToCode,
  toErrorMeta,
  toErrorResult,
  toResolutionResult,
  validateSingleVersionSelector,
  WEBVH_ERROR_TYPES,
} from './resolver-result.js';
export { MultibaseEncoding, multibaseDecode, multibaseEncode } from './utils/multiformats.js';
export {
  convertWebvhIdToWebId,
  createVMID,
  DID_PLACEHOLDER,
  deriveNextKeyHash,
  generateParallelDidWeb,
  getBaseUrl,
  getFileUrl,
  logToJsonlString,
  parseDidKeyDid,
  parseDidKeyVerificationMethod,
  readLogFromString,
} from './utils.js';
export { defaultWebvhLogVerifier } from './verifier.js';
export {
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from './witness.js';
