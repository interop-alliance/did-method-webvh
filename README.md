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

1. In GitHub, go to **Releases** > **Draft a new release**
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
uses [npm OIDC trusted publishing](https://docs.npmjs.com/trusted-publishers) --
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

Resolution rejects a log entry whose `parameters` is not a JSON object or has a
key outside the set `did:webvh:1.0` defines (`scid`, `method`, `updateKeys`,
`nextKeyHashes`, `portable`, `witness`, `watchers`, `ttl`, `deactivated`).
Each parameter value must have the JSON type the specification defines, or be
`null`. A witness `threshold` must be a JSON integer, so a string such as `"2"`
is rejected. A `ttl` must be a JSON integer from 0 to 2^31 - 1 (the RFC 2181
range the specification cites); 0 means the DID should not be cached.

Only `{}` (or `null`) disables witnessing. Any other `witness` value must have
a non-empty `witnesses` array of distinct Ed25519 `did:key` DIDs and a
`threshold` from 1 to the number of witnesses, or resolution fails.
`createDID` and `updateDID` write `{}` when the witness input has no
witnesses.

In the resolution result returned by `resolveDID` (and by `toResolutionResult`),
`didDocumentMetadata.ttl` and `didDocumentMetadata.witness.threshold` are
strings containing integers, since DID resolution metadata does not carry
numbers. `resolveDIDFromLog`
and the `meta` returned by `createDID`, `updateDID`, and `deactivateDID` carry
both as numbers, as do log entries.

## Network access

The library reaches the network in these cases.

- `resolveDID` and `dereference` fetch the DID's `did.jsonl`, unless
  `resolveControlledDid` supplies the log.
- Verifying a log that declares witnesses fetches `did-witness.json` when
  `witnessProofs` is omitted. This covers `resolveDID`, `resolveDIDFromLog`,
  and `updateDID` or `deactivateDID` without `priorMeta`.
- A proof whose verification method is a `did:webvh` DID URL causes that
  DID's log, and its witness file, to be fetched.

The witness URL is derived from the DID inside the log. Whoever wrote the log
therefore picks the host, including `http://localhost` and any port. A server
that verifies logs it did not write should do one of the following.

- Pass `network: 'none'` together with `witnessProofs`.
- Pass `witnessProofs` explicitly.
- Supply its own `fetch` that applies its own destination policy.

Pass `network: 'log-only'` to fetch DID logs and not the witness file. It
permits `did.jsonl`, for the DID and for a `did:webvh` verification method,
and refuses `did-witness.json`.

With `network: 'none'` or `'log-only'`, a log that requires witness proofs
must come with `witnessProofs`. Without them, resolution fails with the `notFound`
resolution error ("Witness proofs not found ... supply witnessProofs"). An
explicit `witnessProofs: []` is checked as an empty proof list, so the
threshold is not met.

The `did.jsonl` and `did-witness.json` fetches are bounded. Each has a 10
second deadline covering the request and the body read, and a 5 MiB body
limit. A declared `content-length` over the limit is rejected up front, a
streamed body is cancelled at the limit, and a response without a WHATWG
stream is measured after `text()`. Redirects are refused, and a response that
reports one (`redirected: true`, or a `url` other than the one requested) is
refused too. These bounds apply to a custom `fetch` as well, which receives
`redirect: 'error'` and an abort `signal` in `init`.

Retrieval failures are thrown as `DIDResolutionError` from
`@interop/data-integrity-core` and keep their `code` in the resolution
result. A 404 or empty `did.jsonl` is `notFound`. Any other HTTP status, a
timeout, an oversized body, a redirect, and an error thrown by `fetch` are
`internalError`. A 404 for `did-witness.json` means there are no witness
proofs. Every other failure is `invalidDid`.

`signWitnessProofEntry` requires `witnessProofs` and does not fetch the
witness file.

## did:vh

`did:vh` is `did:webvh` with the location removed from the DID. A `did:vh`
DID is `did:vh:<scid>`. The log format, SCID and entry-hash algorithms, key
authorization, pre-rotation and witnesses are the same. The client sources
the log and passes it to the resolver.

The API follows the [did:vh Editors Draft v0.1](https://github.com/decentralized-identity/didvh).
It is unstable until the specification reaches Draft status.

Import it from the `/vh` subpath. The function names mirror the `did:webvh`
ones.

```ts
import {
  createDID,
  updateDID,
  deactivateDID,
  resolveDID,
  dereference,
} from '@interop/did-method-webvh/vh';

const { did, log } = await createDID({ signer, updateKeys, verificationMethods });
// did === 'did:vh:<scid>'

const result = await resolveDID(did, { didLog: log });
```

### Create, update, deactivate

`createDID`, `updateDID` and `deactivateDID` take the `did:webvh` options
without `address`, `paths`, `portable` and `alsoKnownAsWeb`. Those have no
meaning without a location, and passing one throws. Entries declare
`method: did:vh:1.0`. An authored `didDocument` names itself
`did:vh:{SCID}`.

Nothing is fetched for the witness proofs of the prior log. Pass them as
`witnessProofs`. An omitted list is read as no proofs.

### Resolve

`resolveDID(did, options)` returns a DID Resolution result and does not
throw. Exactly one of `didLog` and `srcLog` is required.

| Option | Meaning |
| --- | --- |
| `didLog` | The log itself, as JSON Lines text or parsed entries |
| `didWitness` | The witness proofs file, as its parsed JSON array |
| `srcLog` | An absolute URL naming the log file |
| `srcWitness` | An absolute URL naming the witness proofs file |
| `versionId`, `versionTime`, `versionNumber` | At most one version selector |
| `includeDidLog` | Return the verified log and witness file in the resolution metadata |
| `local` | Marks the resolver as local (see below) |
| `verifier`, `resolveVM`, `fetch`, `network` | As for `did:webvh` |

With `didLog` and `didWitness` no network request is made. `srcLog` and
`srcWitness` are retrieved as given, with nothing appended, through the same
bounded fetch as `did:webvh` (deadline, size limit, redirects refused).
`srcWitness` is retrieved only when the log requires witnesses. A missing
witness file is read as one holding no proofs.

`https` references need a domain-name host. Loopback `http` (`localhost`,
`127.0.0.0/8`, `[::1]`) and `file:` references are available only with
`local: true`, and return `invalidOptions` otherwise. Set `local` only for a
resolver used on the same system as its client. A resolver that accepts
requests from other systems must leave it off. Any other scheme returns
`featureNotSupported` when the reference is retrieved, so an unneeded
`srcWitness` in such a scheme is not an error. A reference with user
information, a backslash or a control character returns `invalidOptions`.

With `network: 'none'` neither reference is fetched. With `'log-only'` the
log is fetched and the witness file is not. A `file:` reference is not a
network request.

`includeDidLog: true` adds `didLog` (JSON Lines text, ending at the last
valid entry) and, for a witnessed log, `didWitness` to
`didResolutionMetadata`. Neither is returned when resolution fails.

`checkWatchers`, `extraWatchers` and `minCopies` are validated, and any value
other than the default returns `featureNotSupported`. Copy comparison is not
implemented.

### Rules that differ from did:webvh

- `versionTime` is in whole seconds.
- The `portable` parameter and a JSON `null` parameter value are refused.
  No did:vh result carries a `portable` member in its metadata.
- No entry may follow one that sets `updateKeys` to `[]`.
- While pre-rotation is active, every entry declares `nextKeyHashes`.
- `resolveDID` resolves a log whose later entries fail verification to its
  valid entries, the ones before the first failure. With no version selector
  the result is the last valid entry, with an `invalid-entries` item in
  `didResolutionMetadata.warnings`. A selector that picks a valid entry
  succeeds, and one that picks a later entry is `invalidDid`. A failing
  first entry is `invalidDid`.
- For `resolveDID`, an entry whose witness threshold is not met fails
  verification like any other, so the valid entries end before it.
- `updateDID`, `deactivateDID` and `resolveDIDFromLog` throw on any entry
  that fails verification, as they do for `did:webvh`.
- A retrieval or internal failure during verification (a
  `DIDResolutionError` thrown by a `verifier` or `resolveVM`) is returned
  under its own code. It is not read as an entry failing verification.
- A log declaring a newer `did:vh` `method` version returns
  `featureNotSupported`, unless a selector picks an entry before it. Another
  method's value, or a malformed one, fails verification.
- In the document metadata `ttl` and the witness `threshold` are integers,
  and there is no `portable` member. `ttl`, `witness`, `watchers` and
  `updated` are those of the last valid entry, also when a selector picks an
  earlier one.

### DID URLs and the `src` parameter

`dereference(didUrl, options)` resolves the DID a DID URL names. The URL may
carry `src` and one version parameter:

```ts
await dereference('did:vh:<scid>?src=https%3A%2F%2Fexample.com%2Fusers%2Falice');
// retrieves https://example.com/users/alice/did.jsonl
```

`src` must be an absolute URL with no query or fragment, using `https` or
another scheme with hierarchical paths. `file:` and `http` are refused. One
trailing `/` is removed, then `/did.jsonl` and `/did-witness.json` are
appended to give `srcLog` and `srcWitness`. An invalid `src`, or any other
query parameter, returns `invalidDidUrl`. The derived references are used
only when `options` names no log source of its own. `did:vh` defines no DID
URL path handling, so a URL with a path returns `notFound`. A fragment is not
applied. `deriveSrcReferences(src)` is exported for the derivation alone.

`parseDidVhIdentifier(did, context)` validates a `did:vh` DID and returns its
SCID.

## API Reference

### Core Functions

-
`resolveDID(did: string, options?: ResolutionOptions): Promise<DIDResolutionResult>`
Resolves a DID by fetching its log over HTTPS and returns a DID Resolution
Result envelope.
Pass `options.resolveControlledDid` (an async `(did) => DIDLog | undefined`)
to serve logs the resolver controls itself, such as from local storage. When it
returns a log, the fetch is skipped; when it returns `undefined`, the library
fetches over HTTPS as usual. Either way the log goes through the same SCID and
requested-DID checks. The same callback is consulted when a `did:webvh`
verification method's log is needed during proof verification.
Pass `options.fetch` (a `FetchLike` function) to replace the global `fetch`
used to retrieve the DID log, `did-witness.json`, and any `did:webvh`
verification method's log. This suits environments that cannot patch the
global, such as React Native, proxied or custom-TLS setups, and test
harnesses. `updateDID`, `deactivateDID`, and `createDidWebvhDriver` accept
the same option. The response must provide `ok`, `status`, `text()` and
`json()`. It may also carry `headers` and `body`, which the fetches use to
apply their size limit when `headers.get` and `body.getReader` exist, and
`redirected` and `url`, which are checked for a redirect. An adapter over
another HTTP client can return a plain object with those members.
Pass `options.network: 'none'` to make no network request. See
[Network access](#network-access).

-
`dereference(didUrl: string, options?: ResolutionOptions): Promise<string>`
Dereferences a DID URL with a path, such as
`did:webvh:<scid>:example.com/images/logo.png`, to the URL of the resource it
names, following the specification's DID URL path handling. The DID is
resolved with `resolveDID`. A `versionId`, `versionNumber`, or `versionTime`
DID parameter in the URL selects the version and replaces any version
selector among the options, `verificationMethod` included. The `PathHandler`
service whose `path` is the longest complete match from the beginning of the
DID URL path is selected, and the rest of the path is appended to its
`serviceEndpoint`. The rest of the path starts with `/`, so a trailing `/` on
the endpoint is dropped first. Every `PathHandler` service is handled this
way; the specification's separate `PathService` type is not required. A
trailing `/` on a service `path` is ignored, a `path` that does not start
with `/` never matches, and a `serviceEndpoint` that is not an absolute URI
or carries a query or fragment is rejected. Only the document's own services are
considered; the specification's implicit `#files` and `#whois` services are
not applied. A deactivated DID throws, as does a resolution result that
carries an error, such as an unmet witness threshold. The resource itself is
not fetched.

The steps are exported for callers working from an already-resolved
document: `parseDidUrl` splits a DID URL into DID, path, version selector,
and fragment, optionally narrowed to the DID parameters the caller supports;
`selectPathHandler` picks the service; `pathHandlerUrl` builds the resource
URL; `isPathHandler` tests a service's `type`, and
`PATH_HANDLER_SERVICE_TYPE` names it.

-
`resolveDIDFromLog(log: DIDLog, options?: ResolutionOptions): Promise<{did: string, doc: any, meta: DIDResolutionMeta}>`
Resolves directly from an in-memory DID log.

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
Pass `didDocument` to author the whole document yourself, writing `{SCID}` or
`{DID}` where the not-yet-derived identifier goes. It cannot be combined with
`verificationMethods`, `services`, `alsoKnownAs`, `context`, or the individual
relationship options; `additionalContext` and `alsoKnownAsWeb` do compose with
it.

-
`updateDID(options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog, webDoc?: DIDDoc}>`
Updates an existing DID.
Returns `webDoc` when the updated DID document carries a `did:web:` alias in
`alsoKnownAs`.
**Authored mode:** pass `didDocument` to supply the complete next DID
document. It replaces the prior state outright -- nothing is merged, so
anything omitted is dropped. Every verification method must carry an explicit
`id` and `controller`, and the document `id` must name either the DID being
updated or, on a portable move, the DID being moved from. It cannot be combined
with `verificationMethods`, `services`, `alsoKnownAs`, `context`, or the
individual relationship options; `additionalContext` and `alsoKnownAsWeb` do
compose with it.

**Overlay semantics:** otherwise the prior entry's DID document is carried
forward and only the fields you supply are overwritten. `@context` and `id` are
re-derived and the document `controller` is carried forward untouched;
verification-method fields are preserved unless `verificationMethods` is
passed, and `service` / `alsoKnownAs` / the individual relationship arrays
overwrite only when explicitly supplied. A key-only update (`updateKeys` +
`nextKeyHashes`, no document directives) preserves the prior document
verbatim -- the contract every rotation ceremony relies on.

The `verifier` option on `createDID` / `updateDID` / `resolveDID` /
`resolveDIDFromLog` / `deactivateDID` defaults to `defaultWebvhLogVerifier`
(Ed25519 over `@noble/curves`), so you only pass it when bringing your own
crypto (an `AbstractCrypto` subclass, an HSM-backed verifier, etc.).

-
`deactivateDID(options: DeactivateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}>`
Deactivates an existing DID. The deactivation entry writes `updateKeys: []`
unless `updateKeys` is supplied. Throws while pre-rotation is active; call
`updateDID` with `nextKeyHashes: []` first.

- `generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc`
  Generates the parallel `did:web` document defined by did:webvh v1.0 section 3.7.10.

### Witness Functions

-
`signWitnessProofEntry({ trustedLog, candidateLog, witnessSigner, witnessProofs, verifier? }): Promise<WitnessProofFileEntry>`
Validates a controller-proposed candidate log and signs its final entry as a
witness. The candidate must extend `trustedLog` by exactly one entry (pass an
empty `trustedLog` to sign a genesis entry). The whole candidate is resolved,
the witness thresholds of every earlier version are enforced against
`witnessProofs`, and the signer must be listed in the witness requirement
governing the final entry. Nothing is fetched; pass `[]` when no proofs are
published yet. Returns `{ versionId, proof: [proof] }`, ready to append to
`did-witness.json`.

-
`createWitnessProof(signer, versionId, verificationMethod, created?): Promise<DataIntegrityProof>`
Low-level: creates and signs one witness proof for a specific `versionId`
without validating the log. Prefer `signWitnessProofEntry`.

-
`fetchWitnessProofs(did, fetch?, { timeoutMs?, maxBytes? }): Promise<WitnessProofFileEntry[]>`
Fetches the `did-witness.json` published beside a DID's log. The request has a
10 second deadline (`timeoutMs`) and a 5 MiB body limit (`maxBytes`), and
redirects are refused. A 404 returns an empty list. Any other failure throws
a `DIDResolutionError` with code `internalError`.

### Cryptography Functions

- `createDocumentSigner(options: SignerOptions): Signer`
  Creates a signer for signing DID documents.

- `signerFromExternalKey({ publicKeyMultibase, sign }): Signer`
  Builds a `Signer` around an external signing primitive (KMS, HSM, WebCrypto,
  hardware wallet) whose key is not raw bytes. Prepares the signing input and
  multibase-encodes the signature, and emits the load-bearing
  `did:key:<publicKeyMultibase>#<publicKeyMultibase>` verification-method id the
  resolver requires.

- `signerFromDidKeySigner(signer: ISigner): Signer`
  Builds a `Signer` around a raw-bytes `ISigner` that already carries its own
  `did:key:<publicKeyMultibase>#<publicKeyMultibase>` id (what
  `Ed25519VerificationKey`'s `didKeySigner()` returns). The id is used
  verbatim as the verification-method id; any other id shape is refused.

- `prepareDataForSigning(data: any): Uint8Array`
  Prepares data for signing.

- `createDataIntegrityProofTemplate(options: { verificationMethod: string; created?: string; proofPurpose?: DataIntegrityProofPurpose; id?: string }): DataIntegrityProofTemplate`
  Builds a Data Integrity proof template (type, cryptosuite, verification
  method, created, and proof purpose) from explicit input values.

- `signDataIntegrityProof(document, proofTemplate, signer): Promise<DataIntegrityProof>`
  Signs a document against a proof template and returns a complete
  `DataIntegrityProof`.

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

- `deriveNextKeyHash(key: string): Promise<string>`
  Derives a `nextKeyHashes` entry. Accepts a bare Ed25519 multikey, a
  `did:key` DID, or a `did:key` verification method id, and throws for
  anything else. Returns the spec's **bare base58btc** multihash (NOT
  `z`-prefixed multibase); do not multibase-encode it. The `nextKeyHashes`
  option of `createDID`/`updateDID` and the `nextKeyHashes` parameter of a
  resolved log must hold these derived hashes. A `did:key` or multikey passed
  in their place is rejected.

## License

This project is licensed under the [MIT License](LICENSE).
