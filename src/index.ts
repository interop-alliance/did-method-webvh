export {
  AbstractCrypto,
  createDocumentSigner,
  createProof,
  createSigner,
  prepareDataForSigning,
} from './cryptography.js';
export * from './interfaces.js';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method.js';
export { MultibaseEncoding, multibaseDecode, multibaseEncode } from './utils/multiformats.js';
export { generateParallelDidWeb, parseDidKeyDid, parseDidKeyVerificationMethod } from './utils.js';
export {
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from './witness.js';
