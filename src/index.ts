export { PLACEHOLDER as SCID_PLACEHOLDER } from './constants.js';
export {
  AbstractCrypto,
  createDocumentSigner,
  createProof,
  createSigner,
  prepareDataForSigning,
  signerFromExternalKey,
} from './cryptography.js';
export * from './interfaces.js';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method.js';
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
