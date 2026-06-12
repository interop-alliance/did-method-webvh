# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a TypeScript library implementing the `did:webvh` specification for Decentralized Identifiers (DIDs). It supports two spec versions ([v1.0] and [v0.5]) and provides create, resolve, update, and deactivate operations, plus a CLI tool and example resolver servers.

[v1.0]: https://identity.foundation/didwebvh/v1.0/
[v0.5]: https://identity.foundation/didwebvh/v0.5/

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

- **[src/method.ts](src/method.ts)** — Public API dispatcher. Exports `createDID`, `resolveDID`, `resolveDIDFromLog`, `updateDID`, `deactivateDID`. Routes calls to the correct version implementation based on `method_version` in the DID log.
- **[src/index.ts](src/index.ts)** — Barrel re-export of `method.ts`.
- **[src/cli.ts](src/cli.ts)** — CLI tool wrapping the same operations with file I/O.

### Version Implementations

- **[src/method_versions/method.v1.0.ts](src/method_versions/method.v1.0.ts)** — Current spec (v1.0) implementation of all DID operations.
- **[src/method_versions/method.v0.5.ts](src/method_versions/method.v0.5.ts)** — Legacy spec (v0.5) implementation.

Each version module implements the same operation signatures. `method.ts` selects the right one at runtime.

### Key Supporting Modules

- **[src/cryptography.ts](src/cryptography.ts)** — `AbstractCrypto` base class for implementors to extend. Handles proof creation and data preparation for signing. Consumers implement `sign()` and `verify()`.
- **[src/witness.ts](src/witness.ts)** — Witness proof validation: `verifyWitnessProofs`, `validateWitnessParameter`, `calculateWitnessWeight`, `createWitnessProof`.
- **[src/utils.ts](src/utils.ts)** — Core business logic: DID document construction, hash derivation, log I/O, identifier fetching.
- **[src/interfaces.ts](src/interfaces.ts)** — All TypeScript interfaces (`Signer`, `Verifier`, `DIDDoc`, `DIDLog`, `DIDLogEntry`, etc.).
- **[src/constants.ts](src/constants.ts)** — `METHOD` constant and `PLACEHOLDER` used during DID creation.
- **[src/utils/crypto.ts](src/utils/crypto.ts)**, **[src/utils/buffer.ts](src/utils/buffer.ts)**, **[src/utils/multiformats.ts](src/utils/multiformats.ts)** — Low-level hashing, buffer conversion, and multibase encoding.

### Typical Call Flow

```
createDID(options) [method.ts]
  → method.v1.0.createDID() [method_versions/method.v1.0.ts]
      → prepareDataForSigning() + createProof() [cryptography.ts]
      → DIDLog entry construction [utils.ts]
      → returns { did, doc, log }
```

### Build Output

The library builds with plain `tsc` to a single ESM target with TypeScript declarations in `dist/`. The same files serve Node, browsers (via the consumer's bundler), and React Native. The CLI ships as `dist/cli.js`.

### Test Utilities

**[test/utils.ts](test/utils.ts)** provides `TestCryptoImplementation` (Ed25519 mock), `createTestSigner()`, `createTestVerifier()`, and `createMockDIDLog()` for use across all test files. Tests use Vitest.

### Examples

**[examples/](examples/)** contains reference implementations: `express-resolver.ts` shows how to serve DID resolution over HTTP; `signer.ts` shows how to extend `AbstractCrypto`. The examples are their own private npm package consuming `didwebvh-ts` via a `file:..` dependency, so they import the **built** `dist/` output -- rebuild the library before exercising them.

## Fork Maintenance: Porting Upstream PRs

This repository is maintained as a fork of [decentralized-identity/didwebvh-ts](https://github.com/decentralized-identity/didwebvh-ts). When porting an upstream PR, translate it through the following deliberate divergences (newest first). Library behavior and public API are otherwise kept aligned with upstream.

### Controlled-mode resolution was moved to examples

Upstream's `resolveDID` consults the `DID_VERIFICATION_METHODS` env var (via `getActiveDIDs`) and, for "controlled" DIDs, reads the log from a local `./src/routes/` directory instead of fetching over HTTPS; it returns a `controlled` field in its result. This fork removed all of that from the library: `resolveDID` always resolves over HTTPS and returns no `controlled` field, `fetchLogFromIdentifier` has no `controlled` parameter, and `getActiveDIDs` does not exist. The equivalent logic lives in `resolveDIDLocalFirst` / `readLocalDIDLog` in [examples/express-resolver.ts](examples/express-resolver.ts), and the fixture data moved from `src/routes/` to `examples/routes/`.

**When porting:** upstream changes to `getActiveDIDs`, the `controlled` branch of `fetchLogFromIdentifier`, the `controlled` result field, or `src/routes/` map to `examples/express-resolver.ts` (or are dropped if they only serve the in-library mechanism).

### Build system is plain tsc, not esbuild

Upstream builds with `scripts/build.ts` (esbuild) into four targets (`dist/esm`, `dist/cjs`, `dist/browser`, `dist/cli`) plus a generated `dist/package.json`. This fork deleted that script; `npm run build` is `tsc` emitting a single flat ESM target with declarations to `dist/`, and there is no CJS entry point (Node >= 20.19 can `require()` ESM). The CLI is `dist/cli.js` (upstream: `dist/cli/didwebvh.js`).

**When porting:** upstream changes to `scripts/build.ts` usually have no fork equivalent; genuine build-config changes map to `tsconfig.json` (build) or `tsconfig.dev.json` (type-checking `test/`). Upstream changes to the `exports`/`main`/`browser` fields in `package.json` must be re-expressed against this fork's single-target map.

### Relative imports require explicit .js extensions

This fork compiles with `moduleResolution: nodenext`, so every relative import in `src/` and `test/` carries a `.js` extension (`from './utils.js'`). Upstream uses extensionless imports (`from './utils'`). **When porting:** add `.js` to relative import specifiers in any copied code, then run `npm run lint:fix` (Biome's import ordering can shift once extensions are added).

### Dependency divergences

- Removed unused runtime deps: `cookie`, `glob`, `js-yaml`; removed unused dev deps: `esbuild`, `@sinclair/typebox`, `@types/express`.
- `@stablelib/ed25519` is a runtime dependency here (the unbundled CLI imports it); upstream lists it as a devDependency and relies on bundling.
- Per-port rule of thumb: if an upstream PR adds a dependency, check whether it is actually imported by `src/` before accepting it.

### Bun was removed

Upstream historically used Bun for building/testing; this fork is npm + tsx + Vitest only. Port any `bun`/`bunx` invocations to their `npm`/`npx`/`tsx` equivalents. (Runtime Bun support is unaffected: `isNodeEnvironment` in `src/utils.ts` still treats Bun as Node-like for consumers who run on Bun.)

### Misc deletions

`src/global.d.ts` (unused module declarations) and the `getFS()` require/import-probing fallbacks in `src/utils.ts` were removed -- `getFS()` is now a plain guarded `import('node:fs')`. Upstream patches to those areas likely don't apply.

### Porting checklist

1. Apply the upstream diff, translating per the divergences above.
2. `npm run lint:fix`, then `npm run check`, `npm run build`, `npm test`.
3. Record the port in `CHANGELOG.md` (use `TBD` as the date for unreleased entries) with a reference to the upstream PR number.
