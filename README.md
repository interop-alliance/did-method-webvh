# `@interop/did-method-webvh`

[![CI](https://github.com/interop-alliance/did-method-webvh/actions/workflows/ci.yml/badge.svg)](https://github.com/interop-alliance/did-method-webvh/actions/workflows/ci.yml)
[![NPM Version](https://img.shields.io/npm/v/@interop/did-method-webvh.svg)](https://npm.im/@interop/did-method-webvh)

`@interop/did-method-webvh` provides developers with a comprehensive library for working with
Decentralized Identifiers (DIDs) following the `did:webvh` method specification.
This Typescript-based toolkit is designed to facilitate the integration and
management of DIDs within web applications, enabling secure identity
verification and authentication processes. It includes functions for creating,
resolving, updating and deactivating DIDs by managing DID documents. The package
is built to ensure compatibility with the latest web development standards,
offering a straightforward API that makes it easy to implement DID-based
features in a variety of projects.

## Summary

The `@interop/did-method-webvh` implementation of the [
`did:webvh`]('https://identity.foundation/didwebvh/') specification aims to be
compatible with the `did:webvh` v1.0 specification.

## Examples

The `examples` directory contains sample code demonstrating how to use the
library:

- **Resolver Example**: `examples/express-resolver.ts` (`npm run dev`)
  demonstrates how to implement a DID resolver with Express.js. See
  the [Examples README](./examples/README.md) for more information.
- **Signer Example**: The `examples/signer.ts` (`npm run example:signer`) file
  demonstrates how to implement a custom signer using `AbstractCrypto`.

## Prerequisites

Node.js >= 20.19

## Install dependencies

```bash
npm install
```

## Local development setup

When running the examples from the source checkout, the `@interop/did-method-webvh` package
name resolves to your local build output via the `file:..` dependency in
`examples/package.json`. Run the following once per clone:

```bash
npm run build         # generate the dist/ artifacts
cd examples
npm install           # link the examples to the local build
cd ..
```

After that, you can start the resolver example:

```bash
npm run dev
```

If you ever need to refresh the build (for example after local code changes),
rerun `npm run build`.

## Available Commands

The following commands are defined in the `package.json` file:

1. `dev`: Run the Express resolver example in watch mode for development.

   ```bash
   npm run dev
   ```

This command runs: `tsx watch examples/express-resolver.ts`

1. `test`: Run all tests.

   ```bash
   npm test
   ```

2. `test:watch`: Run tests in watch mode.

   ```bash
   npm run test:watch
   ```

3. `test:bail`: Run tests, stopping on the first failure.

   ```bash
   npm run test:bail
   ```

4. `test:log`: Run tests and save logs to a file.

   ```bash
   npm run test:log
   ```

5. `build`: Build the package.

   ```bash
   npm run build
   ```

6. `build:clean`: Clean the build directory.

   ```bash
   npm run build:clean
   ```

## Releasing

Publishing is **fully automated** and happens **only** when a maintainer
publishes a GitHub Release.

- **Who can publish**: GitHub users with **write**, **maintain**, or **admin**
  permission on this repo.
- **Required tag format**: `vMAJOR.MINOR.PATCH` (for example `v2.7.5`).
- **Required semver bump**: the tag must be a **single** major/minor/patch
  increment over the latest existing `v*` tag.

### How to cut a release

1. In GitHub, go to **Releases** → **Draft a new release**
2. Set **Tag** to the next version, e.g. `v2.7.5`
3. Choose the target branch/commit (typically `main`)
4. Click **Publish release**

That will trigger the publish workflow, which will:

- validate the tag + your repo permission
- set `package.json` version from the tag (without the leading `v`)
- run `npm test` and `npm run build`
- publish to npm

### npm authentication

Publishing
uses [npm OIDC trusted publishing](https://docs.npmjs.com/trusted-publishers) —
the workflow exchanges its GitHub Actions OIDC token for a short-lived npm
publish token at publish time. No static `NPM_TOKEN` is required.

For this to work, the `@interop/did-method-webvh` package on npmjs.com must have a Trusted
Publisher configured pointing at this repository and the
`.github/workflows/publish.yml` workflow.

### Troubleshooting

- **Tag rejected**: make sure it matches `vX.Y.Z` and is exactly one
  major/minor/patch bump over the latest `v*` tag.
- **Permission rejected**: ensure the releasing user has write/maintain/admin
  permission on the GitHub repo.
- **`EOTP` / OTP required at publish**: the npm token path is being used instead
  of OIDC. Make sure no `NODE_AUTH_TOKEN` is set on the publish step and that
  the workflow has `id-token: write` permission.
- **OIDC exchange failed**: confirm the Trusted Publisher config on npmjs.com
  matches this repo's owner, name, and workflow file path (
  `.github/workflows/publish.yml`).

## Creating a DID Resolver

The `@interop/did-method-webvh` library provides the core functionality for resolving DIDs,
but it does not include a built-in HTTP resolver. You can create your own
resolver using your preferred web framework by following these steps:

1. Import the `resolveDID` function from the `@interop/did-method-webvh` library:

   ```typescript
   import { resolveDID } from '@interop/did-method-webvh';
   ```

2. Create endpoints for resolving DIDs:

   ```typescript
   // Example using Express
   app.get('/resolve/:id', async (req, res) => {
     try {
       const result = await resolveDID(req.params.id);
       res.json(result);
     } catch (error) {
       res.status(400).json({
         error: 'Resolution failed',
         details: error.message
       });
     }
   });
   ```

3. Implement file retrieval logic for DID documents and associated resources.

For complete examples, see the [examples](./examples/) directory.

### Resolution metadata notes (v1.0)

For `did:webvh:1.0` resolution flows, resolver failures that invalidate the DID
are surfaced using:

- `meta.error = "invalidDid"`
- `meta.problemDetails` populated with RFC9457-style fields (`type`, `title`,
  `detail`)

Absence cases (for example missing DID log or missing DID URL resource) use:

- `meta.error = "notFound"`

When resolving a requested earlier version (for example with `versionId`,
`versionNumber`, or `versionTime`), the resolver may return a valid earlier
document while still reporting `meta.error = "invalidDid"` if a later log entry
fails verification.

## API Reference

### Core Functions

-
`resolveDID(did: string, options?: ResolutionOptions): Promise<{did: string, doc: any, meta: DIDResolutionMeta, controlled: boolean}>`
Resolves a DID to its DID document.
For `v1.0`, `options.fastResolve` is an opt-in mode defaulting to `false` for
full log parsing.

-
`resolveDIDFromLog(log: DIDLog, options?: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] }): Promise<{did: string, doc: any, meta: DIDResolutionMeta}>`
Resolves directly from an in-memory DID log.
For `v1.0`, `options.fastResolve` is an opt-in mode defaulting to `false` for
full log parsing.

-
`createDID(options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog, webDoc?: DIDDoc}>`
Creates a new DID.
Accepts `address` (`host`, `host:port`, `https://...`, or `did:webvh:...`).
Resolver URL mapping uses `http://localhost` for local testing and `https://`
for non-local hosts.
If `alsoKnownAsWeb: true` is supplied, the result also includes `webDoc`, the
parallel `did:web` DID document to publish as `did.json`.
The `vmIdFragment` option controls verification-method id fragments: `'short'`
(default) uses the last 8 chars of `publicKeyMultibase`; `'multibase'` uses the
full multibase for a self-describing `#<publicKeyMultibase>` fragment.

-
`updateDID(options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog, webDoc?: DIDDoc}>`
Updates an existing DID.
Returns `webDoc` when the updated DID document carries a `did:web:` alias in
`alsoKnownAs`.
**Overlay semantics:** the prior entry's DID document is carried forward and
only the fields you supply are overwritten. `@context`, `id`, and `controller`
are always re-derived; verification-method fields are preserved unless
`verificationMethods` is passed, and `service` / `alsoKnownAs` / the individual
relationship arrays overwrite only when explicitly supplied. A key-only update
(`updateKeys` + `nextKeyHashes`, no document directives) preserves the prior
document verbatim -- the contract every rotation ceremony relies on.

The `verifier` option on `createDID` / `updateDID` / `resolveDID` /
`resolveDIDFromLog` / `deactivateDID` defaults to `defaultWebvhLogVerifier`
(Ed25519 over `@noble/curves`), so you only pass it when bringing your own
crypto (an `AbstractCrypto` subclass, an HSM-backed verifier, etc.).

-
`deactivateDID(options: DeactivateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}>`
Deactivates an existing DID.

- `generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc`
  Generates the parallel `did:web` document defined by did:webvh v1.0 §3.7.10.

### Witness Functions

-
`createWitnessProof(signer, versionId, verificationMethod, created?): Promise<DataIntegrityProof>`
Creates and signs one witness proof for a specific `versionId`.

-
`signWitnessProofEntry(options: WitnessSigningOptions): Promise<WitnessSigningResult>`
Signs one did-witness proof entry (`{ versionId, proof[] }`) for a single target
version.

-
`signWitnessProofEntries(versionIds: string[], witnesses: WitnessEntry[], witnessSignersByDid: Record<string, WitnessSigner>, created?: string): Promise<WitnessSigningResult[]>`
Signs did-witness proof entries for multiple target versions.

### Cryptography Functions

- `createDocumentSigner(options: SignerOptions): Signer`
  Creates a signer for signing DID documents.

- `signerFromExternalKey({ publicKeyMultibase, sign }): Signer`
  Builds a `Signer` around an external signing primitive (KMS, HSM, WebCrypto,
  hardware wallet) whose key is not raw bytes. Prepares the signing input and
  multibase-encodes the signature, and emits the load-bearing
  `did:key:<publicKeyMultibase>#<publicKeyMultibase>` verification-method id the
  resolver requires.

- `prepareDataForSigning(data: any): Uint8Array`
  Prepares data for signing.

- `createProof(options: SigningInput): Promise<SigningOutput>`
  Creates a proof for a DID document.

- `AbstractCrypto`
  An abstract class for implementing custom signers.

### Log and URL Utilities

- `readLogFromString(str: string): DIDLog`
  Parses a JSON Lines (`.jsonl`) DID log. Trims surrounding whitespace, so a
  trailing newline is tolerated; blank lines between entries are not.

- `logToJsonlString(log: DIDLog): string`
  Serializes a DID log to JSON Lines (one entry per line, no trailing newline).
  Inverse of `readLogFromString`; use it to publish `did.jsonl`.

- `getBaseUrl(id: string): string` / `getFileUrl(id: string): string`
  Map a `did:webvh` identifier to its base URL and its `did.jsonl` URL,
  including the port/`%3A` and localhost-`http` rules.

- `convertWebvhIdToWebId(id: string): string`
  Converts a `did:webvh:<scid>:<host>...` id to its parallel `did:web:<host>...`
  id.

- `deriveNextKeyHash(publicKeyMultibase: string): Promise<string>`
  Derives a `nextKeyHashes` entry. Returns the spec's **bare base58btc**
  multihash (NOT `z`-prefixed multibase); do not multibase-encode it.

## License

This project is licensed under the [MIT License](LICENSE).
