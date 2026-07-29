# Agent Guidelines

This file provides guidance to coding agents when working with
code in this repository.

## Overview

This is a TypeScript library implementing the `did:webvh` specification ([v1.0])
for Decentralized Identifiers (DIDs). It provides create, resolve, update, and
deactivate operations, plus example resolver servers.

[v1.0]: https://identity.foundation/didwebvh/v1.0/

## Provenance

Originally forked from
[decentralized-identity/didwebvh-ts](https://github.com/decentralized-identity/didwebvh-ts).

- **Upstream remote:** `up` ->
  `git@github.com:decentralized-identity/didwebvh-ts.git`. Run `git fetch up`
  first; the comparison ref below is `up/main`. (`origin` is the fork,
  `interop-alliance/did-method-webvh`.)
- **Fork point:** `371891f` (upstream PR #115, "fix/linting").

## Commands

```bash
# Run all tests
npm test

# Run a single test file
npx vitest run test/happy-path.test.ts

# Run tests in watch mode, stopping on first failure
npm run test:bail

# Build distribution artifacts
npm run build

# Clean the build output
npm run build:clean

# Type check
npm run check

# Lint (Biome)
npm run lint
```

## Architecture

### Entry Points

- **[src/method.ts](src/method.ts)** -- Public API wrapper. Exports `createDID`,
  `resolveDID`, `resolveDIDFromLog`, `updateDID`, `deactivateDID`. Delegates to
  the spec implementation and adds log fetching, error metadata, and test-log
  capture.
- **[src/index.ts](src/index.ts)** -- Barrel re-export of `method.ts` and the
  supporting modules.

### Spec Implementation

- **[src/method_versions/method.v1.0.ts](src/method_versions/method.v1.0.ts)** --
  Spec (v1.0) entry points for `createDID`, `updateDID`, `deactivateDID`, and
  `resolveDIDFromLog`; merges entry parameters into resolution metadata.
- **[src/method_versions/method.v1.0.entries.ts](src/method_versions/method.v1.0.entries.ts)** --
  Log entry construction: `prepareGenesisEntry`, `prepareUpdateEntry`,
  `prepareDeactivationEntry`, and entry finalization (hashing + signing).
- **[src/method_versions/method.v1.0.resolution.ts](src/method_versions/method.v1.0.resolution.ts)** --
  Log resolution: entry validation, hash-chain and pre-rotation checks,
  witness threshold enforcement, version selection. Logs declaring any other
  `method` version are rejected during resolution.

### Key Supporting Modules

- **[src/cryptography.ts](src/cryptography.ts)** -- `AbstractCrypto` base class
  for implementors to extend; `createDataIntegrityProofTemplate` and
  `signDataIntegrityProof` for proof construction; data preparation for
  signing. Consumers implement `sign()` and `verify()`.
- **[src/witness.ts](src/witness.ts)** -- Witness proof creation and
  validation: `verifyWitnessProofs`, `validateWitnessParameter`,
  `resolveWitnessParameter`, `createWitnessProof`, `signWitnessProofEntries`.
- **[src/did-document.ts](src/did-document.ts)** -- DID document construction
  and queries: `createDIDDoc`, `findVerificationMethod`,
  `generateParallelDidWeb`, placeholder replacement.
- **[src/utils.ts](src/utils.ts)** -- Identifier parsing (
  `parseDidWebvhIdentifier`, `parseCanonicalAddress`), resolution URL
  derivation (`getBaseUrl`, `getFileUrl`), log I/O, and fetching.
- **[src/interfaces.ts](src/interfaces.ts)** -- All TypeScript interfaces (
  `Signer`, `Verifier`, `DIDDoc`, `DIDLog`, `DIDLogEntry`, etc.).
- **[src/constants.ts](src/constants.ts)** -- `METHOD` constant, `PLACEHOLDER`
  used during DID creation, and `VERIFICATION_RELATIONSHIPS`.
- **[src/utils/crypto.ts](src/utils/crypto.ts)**, *
  *[src/utils/buffer.ts](src/utils/buffer.ts)**, *
  *[src/utils/multiformats.ts](src/utils/multiformats.ts)**, *
  *[src/utils/iso8601-datetime.ts](src/utils/iso8601-datetime.ts)** --
  Low-level hashing (`deriveHash`, `deriveNextKeyHash`), buffer conversion,
  multibase encoding, and versionTime parsing/validation.

### Typical Call Flow

```
createDID(options) [method.ts]
  to method.v1.0.createDID() [method_versions/method.v1.0.ts]
      to prepareGenesisEntry() [method_versions/method.v1.0.entries.ts]
          to createDIDDoc() [did-document.ts]
          to createDataIntegrityProofTemplate() + signDataIntegrityProof()
             [cryptography.ts]
      to returns { did, doc, log }
```

### Build Output

The library builds with plain `tsc` to a single ESM target with TypeScript
declarations in `dist/`. The same files serve Node, browsers (via the consumer's
bundler), and React Native.

### Test Utilities

**[test/utils.ts](test/utils.ts)** provides `TestCryptoImplementation` (Ed25519
mock), `createTestSigner()`, `createTestVerifier()`,
`generateTestVerificationMethod()`, and `nextSecond()` for use across all test
files. Tests use Vitest.

### Examples

**[examples/](examples/)** contains reference implementations:
`express-resolver.ts` shows how to serve DID resolution over HTTP; `signer.ts`
shows how to extend `AbstractCrypto`. The examples are their own private npm
package consuming `@interop/did-method-webvh` via a `file:..` dependency, so they import the *
*built** `dist/` output -- rebuild the library before exercising them.

## Fork Maintenance: Porting Upstream PRs

This repository is maintained as a fork
of [decentralized-identity/didwebvh-ts](https://github.com/decentralized-identity/didwebvh-ts).
When porting an upstream PR, translate it through the following deliberate
divergences (newest first). Library behavior and public API are otherwise kept
aligned with upstream.

### The standalone CLI was removed

Upstream ships a CLI (`src/cli.ts`, published as the `didwebvh` bin) wrapping the
library operations with file/env I/O. This fork deleted it: there is no
`src/cli.ts`, no `cli` npm script, no `bin` entry, and no `test/cli-e2e.test.ts`.
CLI workflows live in the separate `did-cli-typescript` project, which consumes
this library's public API (`resolveDID`, `deriveNextKeyHash`, `Signer`/`Verifier`,
etc.) from npm. Removing the CLI also dropped `@stablelib/ed25519` from runtime
`dependencies` (it was only imported by the unbundled CLI) to `devDependencies`.

**When porting:** upstream changes to `src/cli.ts`, the `bin`/`cli` entries, or
CLI tests are **N/A** -- dropped. Upstream changes that touch both the CLI and
the library API (e.g. a new option threaded through `createDID`/`updateDID`) keep
only the library-side change.

### The legacy v0.5 spec implementation was removed

Upstream supports both `did:webvh:1.0` and the legacy `did:webvh:0.5` spec via
`src/method_versions/method.v0.5.ts`, with `src/method.ts` routing operations by
detected version. This fork deleted the v0.5 module; `src/method.ts` always
delegates to the v1.0 implementation, which rejects logs declaring any other
`method` version.

**When porting:** upstream changes to `method.v0.5.ts` are dropped. Upstream
changes to the version-routing logic in `method.ts` map onto this fork's flat
delegation (usually only the v1.0 branch is relevant).

### Controlled-mode resolution was moved to examples

Upstream's `resolveDID` consults the `DID_VERIFICATION_METHODS` env var (via
`getActiveDIDs`) and, for "controlled" DIDs, reads the log from a local
`./src/routes/` directory instead of fetching over HTTPS; it returns a
`controlled` field in its result. This fork removed all of that from the
library: `resolveDID` always resolves over HTTPS and returns no `controlled`
field, `fetchLogFromIdentifier` has no `controlled` parameter, and
`getActiveDIDs` does not exist. The equivalent logic lives in
`resolveDIDLocalFirst` / `readLocalDIDLog`
in [examples/express-resolver.ts](examples/express-resolver.ts), and the fixture
data moved from `src/routes/` to `examples/routes/`.

**When porting:** upstream changes to `getActiveDIDs`, the `controlled` branch
of `fetchLogFromIdentifier`, the `controlled` result field, or `src/routes/` map
to `examples/express-resolver.ts` (or are dropped if they only serve the
in-library mechanism).

### Implicit `#files` / `#whois` services are not injected

Upstream appends default `#files` and `#whois` services to resolved DID
documents: `resolveDIDFromLog` pushes them onto `doc.service` for every log
entry (guarded by a `serviceFragmentExists` check), and `generateParallelDidWeb`
injects the HTTPS-endpoint variants into the parallel `did:web` document. This
fork removed all of it: both functions now pass the DID document's `service`
array through unmodified. The `serviceFragmentExists` helper (`src/utils.ts`),
the `ServiceFragment` enum, and the `SERVICE_TYPE_RELATIVE_REF`,
`SERVICE_TYPE_LINKED_VP`, and `CONTEXT_LINKED_VP` constants (`src/constants.ts`)
were deleted along with it.

**When porting:** upstream changes to implicit-service injection in
`resolveDIDFromLog` or `generateParallelDidWeb` -- or to `serviceFragmentExists`
or the dropped service-type/context constants -- are **N/A**. Upstream changes
that genuinely alter `service` passthrough (validation, ordering) still apply,
minus the injection step.

### `http://localhost` is allowed for local testing

Upstream (PR that landed `8ebada3`, "remove special-casing for localhost,
enforce HTTPS") rejects all `http:` URLs and always builds resolution URLs with
the `https` scheme. This fork deliberately keeps an `http://localhost` escape
hatch for local development and testing: `parseCanonicalAddress` only rejects
`http:` when the host is **not** `localhost`, and `toASCII` / `getBaseUrl` in
[src/utils.ts](src/utils.ts) emit `http` for `localhost` and `https` for every
other host. Non-local hosts are still HTTPS-only, matching upstream.

**When porting:** upstream changes that tighten HTTPS enforcement should preserve
this `localhost`-only `http` exception -- keep the `hostname !== 'localhost'`
guard in `parseCanonicalAddress` and the `localhost` scheme selection in
`toASCII` / `getBaseUrl` rather than reverting to upstream's unconditional
`https`.

### Build system is plain tsc, not esbuild

Upstream builds with `scripts/build.ts` (esbuild) into four targets (`dist/esm`,
`dist/cjs`, `dist/browser`, `dist/cli`) plus a generated `dist/package.json`.
This fork deleted that script; `npm run build` is `tsc` emitting a single flat
ESM target with declarations to `dist/`, and there is no CJS entry point (
Node >= 20.19 can `require()` ESM).

**When porting:** upstream changes to `scripts/build.ts` usually have no fork
equivalent; genuine build-config changes map to `tsconfig.json` (build) or
`tsconfig.dev.json` (type-checking `test/`). Upstream changes to the `exports`/
`main`/`browser` fields in `package.json` must be re-expressed against this
fork's single-target map.

### Relative imports require explicit .js extensions

This fork compiles with `moduleResolution: nodenext`, so every relative import
in `src/` and `test/` carries a `.js` extension (`from './utils.js'`). Upstream
uses extensionless imports (`from './utils'`). **When porting:** add `.js` to
relative import specifiers in any copied code, then run `npm run lint:fix` (
Biome's import ordering can shift once extensions are added).

### Dependency divergences

- Removed unused runtime deps: `cookie`, `glob`, `js-yaml`; removed unused dev
  deps: `esbuild`, `@sinclair/typebox`, `@types/express`.
- `@stablelib/ed25519` is a **devDependency** here (used only by tests and the
  `examples/`); upstream also lists it as a devDependency. (It was briefly a
  runtime dep while the standalone CLI existed -- see "The standalone CLI was
  removed" below.)
- Per-port rule of thumb: if an upstream PR adds a dependency, check whether it
  is actually imported by `src/` before accepting it.

### Bun was removed

Upstream historically used Bun for building/testing; this fork is npm + tsx +
Vitest only. Port any `bun`/`bunx` invocations to their `npm`/`npx`/`tsx`
equivalents. (Runtime Bun support is unaffected: `isNodeEnvironment` in
`src/utils.ts` still treats Bun as Node-like for consumers who run on Bun.)

### Misc deletions

`src/global.d.ts` (unused module declarations) and the `getFS()`
require/import-probing fallbacks in `src/utils.ts` were removed -- `getFS()` is
now a plain guarded `import('node:fs')`. Upstream patches to those areas likely
don't apply.

### Porting checklist

1. Apply the upstream diff, translating per the divergences above.
2. `npm run lint:fix`, then `npm run check`, `npm run build`, `npm test`.
3. Record the port in `CHANGELOG.md` (use `TBD` as the date for unreleased
   entries) with a reference to the upstream PR number.

`npm run check` is the only thing that type-checks `test/` -- Vitest transpiles
each test file in isolation and never cross-checks types, so a test file can pass
its own assertions while referencing an option that no longer exists. When a port
renames or removes a public option, sweep **all** of `test/` for the old name, not
just the files the upstream diff touched. (`npm test` runs `check` first, and a
Stop hook in [.claude/settings.json](.claude/settings.json) runs it again, so a
missed call site fails locally rather than in CI.)
