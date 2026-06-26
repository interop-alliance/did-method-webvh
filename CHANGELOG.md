## 3.5.1 - TBD

### Fixed

* `createNextVersionTime` now keeps `versionTime` strictly increasing when
  consecutive entries land in the same wall-clock second. Since `versionTime` is
  trimmed to whole seconds (3.4.0+), a rapid create-then-update produced an equal
  timestamp that the resolver rejects (`versionTime for version 'N' must be
  greater than previous entry time`). It now bumps a colliding `now` to
  `previous + 1s`, and the `requestedVersionTime` branch compares the formatted
  (whole-second) value so a sub-second request that trims down to the previous
  second is rejected rather than emitting a collision. Restores parity with
  canonical upstream `didwebvh-ts` (the `previous + 1000` fallback was dropped in
  the 3.4.0 whole-second port).

## 3.5.0 - 2026-06-25

### Added

* `@interop/did-method-webvh/driver` subpath export with `createDidWebvhDriver()`
  -- a did-io-compatible `{ method, get }` driver for JSON-LD document loaders
  (e.g. `@interop/security-document-loader`'s `CachedResolver`). It resolves
  `did:webvh` DIDs and dereferences `did#fragment` verification methods over
  `resolveDID`, with fragment dereferencing inlined (no `@interop/did-web-resolver`
  dependency) and the did-io driver shape implemented as a plain literal (no
  `@interop/did-io` dependency). History-log proofs are verified with a
  caller-supplied `verifier`, defaulting to the new `defaultWebvhLogVerifier`
  (Ed25519 over `@noble/curves`), so the core stays crypto-agnostic. The root
  export is unchanged -- resolver-only consumers pull none of the driver code.
* `@noble/curves` dependency, reachable only via the `/driver` subpath.

### Changed

* Removed the hand-rolled `deepClone` helper from `src/utils.ts` in favor of the
  global `structuredClone` (available on all supported runtimes, including React
  Native 0.75+). All call sites in `src/utils.ts` and
  `src/method_versions/method.v1.0.ts` now use `structuredClone`; behavior is
  unchanged (it preserves `Date` instances, the one case the old helper
  special-cased).
* `versionTime` is now trimmed to whole-second accuracy (`createDate` in
  `src/utils.ts` drops sub-second milliseconds), and `updateDID` uses the real
  wall-clock time instead of auto-bumping to `previous + 1ms` when no `updated`
  is supplied (`createNextVersionTime` in `src/utils/iso8601-datetime.ts`).
  Ports upstream `12244b0`. Tests that chain rapid sequential `updateDID` /
  `deactivateDID` calls now thread an explicit `updated` via a new `nextSecond`
  test helper (`test/utils.ts`) and wait for a second boundary before
  re-deactivation (ports upstream `053ff0c` and `c759c43`; the latter's
  `Bun.sleep` is translated to `setTimeout` for this de-Bunned fork).
* Condensed the controller-computation comment in
  `src/method_versions/method.v1.0.ts` (ports upstream `3f20a7f`).
* Tightened type safety in `src/utils.ts`: genericized
  `replaceValueInObject<T>`, widened `deriveHash` / `getCachedHash` /
  `setCachedHash` inputs from `any` to `unknown`, and typed `normalizeVMs`,
  `isNodeEnvironment`, and `findVerificationMethod` without `any`. Removed the
  unused deprecated `clone` export. Flipped Biome's `noExplicitAny` from `off`
  to `error` for `src/` and `test/` (the `examples/` / `scripts/` override stays
  `off`), and removed the remaining explicit `any`s from the test suite to
  satisfy it. Ports the library-side portion of upstream `e58fe36` (its
  `src/cli.ts` changes are N/A for this fork).
* Replaced the remaining `as unknown as DIDLogEntry` / `as unknown as DIDLog`
  double-casts in `test/cryptography.test.ts` and `test/features.test.ts` with
  properly typed `DIDLogEntry` objects (full `versionId` / `versionTime` /
  `parameters` / `state` shape and a `proof: [...]` array). Ports the remaining
  applicable portion of upstream `988cf46`; most of that commit's `any`
  removals were already done in this fork's `e58fe36` pass, and its
  `test/cli-e2e.test.ts` change is N/A.

## 3.4.0 - 2026-06-25

### Removed

* Implicit `#files` / `#whois` service injection. `resolveDIDFromLog` no longer
  appends default `#files`/`#whois` services to resolved DID documents, and
  `generateParallelDidWeb` no longer injects them into the parallel `did:web`
  document -- both now pass the DID document's `service` array through
  unmodified. Dropped the now-unused `serviceFragmentExists` helper from
  `src/utils.ts` and the `ServiceFragment` enum plus
  `SERVICE_TYPE_RELATIVE_REF`, `SERVICE_TYPE_LINKED_VP`, and `CONTEXT_LINKED_VP`
  constants from `src/constants.ts`.

## 3.3.0 - 2026-06-24

### Added

* `src/utils/iso8601-datetime.ts` with strict, calendar-correct ISO8601
  validation (`ISO8601_DATETIME_REGEX`, `parseUtcIso8601VersionTime`,
  `validateUtcIso8601NotInFuture`, `createNextVersionTime`). `versionTime` values
  must now be UTC (`Z` or `+00:00`) with full calendar correctness (leap years,
  per-month day ranges). Ported from upstream PRs
  [#120](https://github.com/decentralized-identity/didwebvh-ts/pull/120) and
  [#121](https://github.com/decentralized-identity/didwebvh-ts/pull/121).
* `validateMethodSpecificPathSegments` and `parseDidWebvhIdentifier` (the latter
  returning a structured `{ scid, didDomainComponent, paths, locationKey }`) in
  `src/utils.ts`. Ported from upstream PR
  [#120](https://github.com/decentralized-identity/didwebvh-ts/pull/120).
* SCID multihash algorithm enforcement: SCIDs must use SHA-256 (multihash code
  `0x12`); other algorithms are rejected in `scidIsFromHash`. Ported from
  upstream PR
  [#121](https://github.com/decentralized-identity/didwebvh-ts/pull/121).
* `serviceFragmentExists` in `src/utils.ts`, matching both `#files`/`#whois`
  fragment form and the absolute `did:webvh:...#files` form when deciding whether
  to inject implicit services. New method-version constants in
  `src/constants.ts` (`METHOD_VERSION_1_0`, `METHOD_PROTOCOL_V1_0`,
  `METHOD_PARAMETER_KEYS`, `ServiceFragment`, service-type/context/error-type
  constants). Ported from upstream PR
  [#121](https://github.com/decentralized-identity/didwebvh-ts/pull/121).
* `requestedDid` resolution option: when set, resolution fails unless some log
  version's `state.id` matches it. Threaded through `resolveDID`. Ported from
  upstream PR
  [#121](https://github.com/decentralized-identity/didwebvh-ts/pull/121).
* `address` and `paths` options on `updateDID` (for parity with `createDID`). A
  portable DID can now move to a new location: the controller is rebuilt from the
  requested `address`/`domain`/`paths` while preserving the SCID. Re-passing a
  bare domain on a pathed DID preserves the prior paths instead of dropping them.
  Ported from upstream PR
  [#127](https://github.com/decentralized-identity/didwebvh-ts/pull/127).

### Changed

* Ported straggling runtime type-safety hardening from upstream to `src/utils.ts`:
  `validateDidKeyMultibase` now extracts the caught error message defensively
  (`error instanceof Error ? error.message : String(error)`); `resolveVM` throws
  a "not found" error when `resolveDIDFromLog` yields no document instead of
  passing it on; `findVerificationMethod` is typed `(doc: DIDDoc, ...)` and guards
  relationship-array entries against non-objects; and `writeVerificationMethodToEnv`
  guards the decoded env payload with `Array.isArray` before reuse.
* Implicit `#files`/`#whois` services now reference the `SERVICE_TYPE_RELATIVE_REF`,
  `SERVICE_TYPE_LINKED_VP`, and `CONTEXT_LINKED_VP` constants from
  `src/constants.ts` instead of hardcoded string literals, matching upstream.
* `updateDID` parameter and DID-document handling now match upstream:
  - Sparse updates preserve prior DID document state: the previous entry's
    `state` is carried forward and only the fields an update actually supplies
    (`verificationMethods`, `services`, `authentication`, `assertionMethod`,
    `keyAgreement`, `alsoKnownAs`) are overlaid, instead of rebuilding the
    document from scratch. Ported from upstream
    `keep prior DIDDoc state with sparse updateDID() calls` (commit `1459ed6`).
  - `updateKeys` is omitted from an update entry's `parameters` when unchanged
    and not under active pre-rotation (and inherited from the prior entry while
    pre-rotation is active), rather than always being written; resolution tracks
    it via the presence of the key. `nextKeyHashes` is likewise only written
    when explicitly supplied, so an omitted value inherits the prior
    pre-rotation state. Ported from upstream `track updateKeys` (commit
    `5bc85bf`).
  - Pre-rotation key commitment is now enforced at write time: `updateDID`
    rejects an omitted `updateKeys` while pre-rotation is active
    (`updateKeys must be provided while pre-rotation is active`) and rejects
    update keys not committed in the prior entry's `nextKeyHashes`
    (`Invalid update key`) before the entry is produced, in addition to the
    existing read-time check. Ported from upstream
    `enforce pre-rotation key commitment` (commit `b40eb06`).
* Type-safety hardening across the public surface (no behavior change). `Signer`
  and `SigningInput` are now generic over a `SignableDocument` union;
  `createDocumentSigner` is generic and returns `TDocument & { proof }`;
  `VerificationMethod.publicKeyJwk` is typed `JsonObject` and
  `ServiceEndpoint.serviceEndpoint` is typed with `JsonValue` instead of `any`.
  `catch (e: any)` blocks now use `e instanceof Error` narrowing. `updateDID`
  service params are typed `ServiceEndpoint[]`. The CLI gains
  `requirePublicKeyMultibase`/`parseExplicitPaths` helpers, typed
  `resolutionOptions`/`envVMs`, and honors `--update-key` when selecting the
  signing verification method. Ported from upstream PR
  [#119](https://github.com/decentralized-identity/didwebvh-ts/pull/119).
* `updateDID` now rejects `portable: true` in an update entry (portability can
  only be enabled in the first entry) and refuses to move a DID whose
  portability is disabled (`Cannot move DID: portability is disabled`).
  `portable: false` in an update is permitted and permanently locks portability
  off. `verificationMethod` is included in the historical-selector determination
  so a requested-but-absent VM resolves to the last valid document plus an error
  rather than `null`. Ported from upstream PR
  [#129](https://github.com/decentralized-identity/didwebvh-ts/pull/129).

* **Breaking:** `resolveDIDFromLog` now returns `doc: DIDDoc | null`. A
  deactivated DID resolved without an explicit historical selector returns
  `doc: null`, and an explicit selector (`versionNumber` / `versionId` /
  `versionTime` / `verificationMethod`) that matches no entry returns
  `doc: null` with a `NotFound` error rather than falling back to the last valid
  document. Ported from upstream PR
  [#121](https://github.com/decentralized-identity/didwebvh-ts/pull/121).
* resolution enforces strict `versionId` structure (`parseAndValidateVersionId`:
  exactly one `-`, numeric version prefix, non-empty hash, version equal to the
  entry index + 1) and stricter method-parameter rules for entries after the
  first: `scid` must not reappear, `method` must not change away from
  `did:webvh:1.0`, `portable: true` may only be enabled in the first entry, and
  `portable: false` permanently locks portability off. Each entry's `state.id`
  SCID must match the log's SCID. Ported from upstream PR
  [#121](https://github.com/decentralized-identity/didwebvh-ts/pull/121).
* `did:key` verification-method parsing now rejects a fragment that does not
  equal the key multibase. Ported from upstream PR
  [#121](https://github.com/decentralized-identity/didwebvh-ts/pull/121).
* witness-parameter validation now rejects any witness `did:key` whose multikey
  is not Ed25519 (multicodec `0xed01`), per did:webvh v1.0. Ported from upstream
  PR [#120](https://github.com/decentralized-identity/didwebvh-ts/pull/120).

* resolution now enforces `versionTime` on every log entry: it is **required**
  (a log entry missing `versionTime` is rejected), must be **strictly
  increasing** across entries (reordering defense), and must not be more than 5
  minutes in the future (clock-skew tolerance).
* address / host / path-segment parsing is hardened against path-traversal and
  injection: `parseCanonicalAddress` (and therefore `createDID` path handling)
  now rejects `.`/`..` dot-segments, decoded `/`/`\`/NUL within a single path
  segment, leading/trailing whitespace, malformed percent-encoding, and `?`/`#`
  query/fragment components in address, DID-domain, and path contexts. Pre-encoded
  `%3a` port separators are accepted case-insensitively. The fork's
  `http://localhost` affordance for local testing is preserved (upstream enforces
  HTTPS-only).
* `createDID` / `updateDID` validate any caller-supplied `created` / `updated`
  timestamp is not in the future, and `updateDID` / `deactivateDID` now derive a
  strictly monotonic `versionTime` via `createNextVersionTime`.
* `createDate()` now emits full millisecond precision (`toISOString()`) instead
  of truncating to whole seconds, so consecutive entries generated in the same
  second remain strictly increasing.

### Removed

* **Breaking:** the standalone CLI (`src/cli.ts`, the `didwebvh` `bin`, the `cli`
  npm script, and `test/cli-e2e.test.ts`). CLI workflows now live in the separate
  `did-cli-typescript` project, which consumes this library's public API. As a
  result `@stablelib/ed25519` -- previously a runtime dependency only because the
  unbundled CLI imported it -- moved to `devDependencies`, shrinking the published
  package's runtime closure to `@noble/hashes` and `json-canonicalize`.
* **Breaking:** the non-normative `fastResolve` resolution option. The spec
  mandates full verification of every log entry, so resolution always verifies
  every entry's proof; there is no opt-in fast path. Ported from upstream PR
  [#120](https://github.com/decentralized-identity/didwebvh-ts/pull/120).

### Tests

* Backfilled `method.v1.0` coverage: `updateDID` with explicit
  `assertionMethod`/`keyAgreement` options (`happy-path`), resolution of a log
  using the legacy `witnesses`/`witnessThreshold` parameter format
  (`witness`), and error-case coverage in `not-so-happy-path` (missing
  `updateKeys`, missing `address`/`domain`, missing `verificationMethods`,
  out-of-order version number, missing/non-monotonic `versionTime`, mismatched
  `scid` option, matching `requestedDid`, and update/deactivate of an
  already-deactivated DID). `resolve` now asserts a non-existent
  `verificationMethod` resolves to `doc: null` with a `NotFound` error, and
  `watchers` asserts the cleared-watchers (`[]`) shape. Ported from upstream PRs
  [#129](https://github.com/decentralized-identity/didwebvh-ts/pull/129) and
  [#131](https://github.com/decentralized-identity/didwebvh-ts/pull/131).
* Further backfilled `method.v1.0` coverage against upstream's
  `enhance test coverage of method.v1.0` change: `versionTime` clock-skew
  tolerance (accepts up to, rejects beyond, 5 minutes in the future, via a new
  `createFutureDIDLog` test helper), `versionId` structural validation
  (missing/multiple `-` separators, empty hash component), rejection of unknown,
  downgraded, or `scid`-bearing `method`/parameters in later entries, rejection
  of a non-SHA-256 SCID multihash, `requestedDid` mismatch and not-present
  cases, the empty-log "no entries to process" case, and historical
  `versionId`/`versionTime` selectors that stay successful when a later entry is
  corrupted (`not-so-happy-path`); explicit `versionId`/`versionTime` misses
  returning `NotFound` without a latest fallback, explicit empty
  `nextKeyHashes` disabling pre-rotation, and absolute service IDs preventing
  implicit `#files` duplication (`features`); the `did:key` verificationMethod
  fragment-mismatch rejection (`witness`); rejection of a pass-through
  `didDocument` whose substituted id does not match the created DID
  (`did-document-passthrough`); and rejection of DID identifiers containing
  fragment/query contamination or traversal-style path segments (`resolve`).
* Coverage for the `updateDID` behavior changes above (see _Changed_): sparse
  updates preserving prior `alsoKnownAs`/`service` state and omitted
  `updateKeys` staying omitted from update parameters (`happy-path`); omitted
  `nextKeyHashes` inheriting prior pre-rotation state and omitted `updateKeys`
  being rejected while pre-rotation is active (`features`). The existing
  pre-rotation tests were updated for write-time enforcement: `updateKeys MUST
  be in previous nextKeyHashes when updating` now asserts `updateDID` itself
  rejects, `updateKeys MUST be in nextKeyHashes when reading` hand-builds the
  offending entry to still exercise the read-time check, and the now-redundant
  `Require nextKeyHashes to continue if previously set` test was removed.

## 3.2.0 - 2026-06-24

### Added

* export `deriveNextKeyHash` from the package entry, so callers implementing
  key pre-rotation can compute the committed `nextKeyHashes` value
  (`base58btc(multihash_sha2_256(sha256(utf8Bytes(publicKeyMultibase))))`)
  without reaching into internal module paths.

## 3.1.0 - 2026-06-15

### Added

* support `capabilityDelegation` and `capabilityInvocation` as verification
  relationship options on `createDID` / `updateDID` (alongside the existing
  `authentication`, `assertionMethod`, and `keyAgreement` passthroughs), so a
  single verification method can be referenced by id across all five
  relationships -- matching the `did:web` shape -- instead of being limited to
  the one relationship implied by its `purpose`.
* a verification method's `purpose` may now be an **array** of relationships
  (`DataIntegrityProofPurpose[]`), not just a single value. A key declared with
  `purpose: ['authentication', 'assertionMethod', 'capabilityDelegation',
  'capabilityInvocation']` is added once to `verificationMethod` and referenced
  by id from each listed relationship -- the ergonomic way to produce the
  `did:web` shape without building relationship-id strings by hand. A single
  string still works; absent (or empty) still defaults to `authentication`.
* export `DID_PLACEHOLDER` (the `{DID}` substitution token) and `createVMID`
  from the package entry, so callers can construct verification-method id
  references (e.g. `` `${DID_PLACEHOLDER}#${publicKeyMultibase.slice(-8)}` ``)
  without depending on internal magic strings.

### Changed

* `normalizeVMs` no longer copies the creation-time `purpose` directive onto the
  emitted `verificationMethod` entries; `purpose` is not a DID Core
  verification-method property and previously leaked into the published DID
  document. The relationship arrays (`authentication`, etc.) are unaffected.

## 3.0.0-3.0.2 - 2026-06-14

### Package

* rename the package from `didwebvh-ts` to `@interop/did-method-webvh` and move
  the repository to `interop-alliance/did-method-webvh`; update import specifiers
  and docs accordingly (the `didwebvh` CLI bin name is unchanged)

### BREAKING CHANGES

* remove the legacy `did:webvh:0.5` spec implementation (`src/method_versions/method.v0.5.ts`); the library now supports `did:webvh:1.0` only:
  * resolving a DID log whose first entry declares `method: 'did:webvh:0.5'` (including via `updateDID`/`deactivateDID`, which resolve the log internally) throws `'did:webvh:0.5' is not a supported method version.`
  * `createDID` throws the same error if passed an explicit non-1.0 `method` option (previously an untyped option that selected the v0.5 implementation)
* remove "controlled-mode" local file resolution from the library; it now lives in `examples/express-resolver.ts`:
  * `resolveDID` no longer consults the `DID_VERIFICATION_METHODS` env var or reads DID logs from the local `./src/routes/` directory; it always resolves over HTTPS
  * `resolveDID` no longer returns a `controlled` field in its result (success or error)
  * `fetchLogFromIdentifier` loses its second (`controlled`) parameter
  * the internal `getActiveDIDs` helper is removed (it was not exported from the package entry point)
  * the `src/routes/` fixture data moves to `examples/routes/`
  * servers that control their own DID logs should read the log file themselves and call the existing `resolveDIDFromLog` export (see `resolveDIDLocalFirst` in `examples/express-resolver.ts` for a reference implementation)

### Build System

* replace the esbuild multi-bundle build (ESM/CJS/browser/CLI) with a plain `tsc` build emitting a single ESM target plus declarations to `dist/`; the `require` entry point is dropped (Node >= 20.19 can `require()` ESM natively)
* remove unused dependencies (`cookie`, `glob`, `js-yaml`) and unused dev dependencies (`esbuild`, `@sinclair/typebox`, `@types/express`)
* move `@stablelib/ed25519` to `dependencies` (the unbundled CLI imports it at runtime)
* the CLI now ships as `dist/cli.js` (was `dist/cli/didwebvh.js`); the `didwebvh` bin name is unchanged
* upgrade `vitest` from v3 to v4 (no test or config changes required)

### Tests

* add test coverage measurement: `@vitest/coverage-v8` dev dependency and a `test:coverage` script (informational only, no thresholds; the CLI is exercised via subprocesses, which V8 coverage cannot see)
* add tests for the HTTPS resolution path (`resolveDID`, `fetchLogFromIdentifier`, `fetchWitnessProofs`) using a stubbed global `fetch`, covering success, 404/notFound mapping, empty and invalid logs, SCID mismatch, and network failure
* add unit tests for multibase/multihash decode error branches, the buffer utilities (both Node and browser paths), and the hash helpers

## [2.7.4](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.7.3...v2.7.4) (2026-04-24)


### Bug Fixes

* default verification method controller to the DID ([f3ac134](https://github.com/decentralized-identity/didwebvh-ts/commit/f3ac134278871bf059c60f0be2c7da5889264a3c))

## [2.7.3](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.7.2...v2.7.3) (2026-04-18)


### Bug Fixes

* entry hash bug ([cf948fe](https://github.com/decentralized-identity/didwebvh-ts/commit/cf948fe8d8401b69a1ab0b0a974d80aa64bb0af6))

## [2.7.2](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.7.1...v2.7.2) (2026-03-03)


### Bug Fixes

* resolver integrity and validation hardening ([a4b6b27](https://github.com/decentralized-identity/didwebvh-ts/commit/a4b6b277862258cafb7be17c0a7810c3123e792c))

## [2.7.1](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.7.0...v2.7.1) (2026-01-24)


### Bug Fixes

* remove npm token ([c9fb8a3](https://github.com/decentralized-identity/didwebvh-ts/commit/c9fb8a3280466f31ccb31a66cd25562a823dd7ad))
* update node version in action ([49e07b0](https://github.com/decentralized-identity/didwebvh-ts/commit/49e07b01a4b87047900d2ab30aff7189660ee506))
* updated semantic release ([1802ea5](https://github.com/decentralized-identity/didwebvh-ts/commit/1802ea526f75f7c08b0b2fc861a2743cf0080b4c))

# [2.7.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.6.0...v2.7.0) (2026-01-24)


### Features

* add id token perm to publish action ([07d801d](https://github.com/decentralized-identity/didwebvh-ts/commit/07d801deceae05b88e236e1bdd9f333cce98c86d))

# [2.6.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.7...v2.6.0) (2026-01-24)


### Features

* bump version ([e1c4a29](https://github.com/decentralized-identity/didwebvh-ts/commit/e1c4a29a4b4fe6fc6530f3f4987f0cab92079396))

## [2.5.7](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.6...v2.5.7) (2026-01-23)


### Bug Fixes

* updated dependencies for security vulnerabilities ([2c0ac78](https://github.com/decentralized-identity/didwebvh-ts/commit/2c0ac787e75a29382788f903286bdc0fc7f13fb1))

## [2.5.6](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.5...v2.5.6) (2025-11-12)


### Bug Fixes

* correct host normalization in toASCII for numeric domains like 2060.io ([b226c69](https://github.com/decentralized-identity/didwebvh-ts/commit/b226c69da1d77391b4f4c7d51144f47bab64f326))

## [2.5.5](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.4...v2.5.5) (2025-10-08)


### Bug Fixes

* allow verification methods without publicKeyMultibase ([ebe9822](https://github.com/decentralized-identity/didwebvh-ts/commit/ebe9822c0dd40dc8fbd7b56213c7a4734f75658c))

## [2.5.4](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.3...v2.5.4) (2025-09-02)


### Bug Fixes

* remove extra comma ([70ee446](https://github.com/decentralized-identity/didwebvh-ts/commit/70ee446c9192128eabd084c8b278783e7363a7fd))
* update DID without recalculating verification methods ([15c47e7](https://github.com/decentralized-identity/didwebvh-ts/commit/15c47e7e6050a895eab7ee4abc55fe45baa94de3))

## [2.5.3](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.2...v2.5.3) (2025-08-15)


### Bug Fixes

* remove base externals from build configurations ([18a7a23](https://github.com/decentralized-identity/didwebvh-ts/commit/18a7a2339895155e6fa10c9a9dab23fccf29a203))

## [2.5.2](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.1...v2.5.2) (2025-08-14)


### Bug Fixes

* enhance environment detection and dynamic fs import handling ([474fd2c](https://github.com/decentralized-identity/didwebvh-ts/commit/474fd2ccac84ef2c5ce6755d244dbbf10472c9ac))

## [2.5.1](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.5.0...v2.5.1) (2025-08-14)


### Bug Fixes

* update React Native entry points in package.json ([95ad5d8](https://github.com/decentralized-identity/didwebvh-ts/commit/95ad5d88f2796b28bf45048452b4ddeaec586e16))

# [2.5.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.4.1...v2.5.0) (2025-08-14)


### Features

* add support for React Native in package.json ([2f16d19](https://github.com/decentralized-identity/didwebvh-ts/commit/2f16d19e5d03a8afe538dabe1ca50d0a87f7e5dc))

## [2.4.1](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.4.0...v2.4.1) (2025-07-23)


### Bug Fixes

* enhance verification method handling and improve CLI tests ([275152e](https://github.com/decentralized-identity/didwebvh-ts/commit/275152e1d545051dfef673474c3ec4505ba47f94))

# [2.4.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.3.2...v2.4.0) (2025-07-16)


### Bug Fixes

* update witness parameter handling and types ([c783641](https://github.com/decentralized-identity/didwebvh-ts/commit/c783641ad318565923fcfcd896ab44370c39363f))


### Features

* enhance cryptographic interface and implementation ([a37c99b](https://github.com/decentralized-identity/didwebvh-ts/commit/a37c99b7bf1d53ba607f1038c21c3265ff05f091))
* enhance witness handling and resolution logic ([cb453a8](https://github.com/decentralized-identity/didwebvh-ts/commit/cb453a852cfcab2b474bf1c650f41362bd31f2b2))
* implement witness proof generation and enhance CLI functionality ([84bbc4f](https://github.com/decentralized-identity/didwebvh-ts/commit/84bbc4f79140c102af54a0a7d91ff1a7725ed048))

## [2.3.2](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.3.1...v2.3.2) (2025-06-24)


### Bug Fixes

* improve dynamic filesystem module loading ([817897e](https://github.com/decentralized-identity/didwebvh-ts/commit/817897e2fea7183ab46bda2d16b69325f9f0ff79))

## [2.3.1](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.3.0...v2.3.1) (2025-06-24)


### Bug Fixes

* update log handling to use async/await ([31067af](https://github.com/decentralized-identity/didwebvh-ts/commit/31067af464b802463859352a49291c02ac111857))

# [2.3.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.2.0...v2.3.0) (2025-06-23)


### Bug Fixes

* improve filesystem access handling in utils ([ec72a75](https://github.com/decentralized-identity/didwebvh-ts/commit/ec72a75b0efa757fe5e76ce1d7f522ed56377c6b))


### Features

* add paths support in DID creation and testing ([ee51df5](https://github.com/decentralized-identity/didwebvh-ts/commit/ee51df52059a06d583eece78bc8aad9e9abc9802))

# [2.2.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.1.0...v2.2.0) (2025-06-18)


### Bug Fixes

* improve test script logging and cleanup ([4df9663](https://github.com/decentralized-identity/didwebvh-ts/commit/4df9663d7a702c9a586cb1dbebb380e39ca85707))


### Features

* add watcher support to DID creation and updates ([8d206bd](https://github.com/decentralized-identity/didwebvh-ts/commit/8d206bdf1452d435f2c370e1753c22799f5dc8ec))
* enhance DID resolution error handling and add ProblemDetails interface ([b331c46](https://github.com/decentralized-identity/didwebvh-ts/commit/b331c4630d35005d66bea80bb2904c5bfe1ee415))
* enhance error handling and status code mapping in DID resolution ([849d0c6](https://github.com/decentralized-identity/didwebvh-ts/commit/849d0c60ef04efb17c66e155bc3072273a166ac2))
* enhance internationalized domain handling in utils ([f19f831](https://github.com/decentralized-identity/didwebvh-ts/commit/f19f831e4463071e06c50b6966ae4a6769fc0ce3))
* enhance test logging functionality in DID operations ([8d66bcc](https://github.com/decentralized-identity/didwebvh-ts/commit/8d66bcce45a287f1e953bcff662d92c99615d10c))
* implement domain encoding in DID creation ([4369f70](https://github.com/decentralized-identity/didwebvh-ts/commit/4369f706a83134b9b1cfabcc5e6f802262863e26))
* improve filesystem access and domain handling in utils ([f6a6154](https://github.com/decentralized-identity/didwebvh-ts/commit/f6a61548543f130a02e89008c880ceba307f28b6))
* update examples and scripts for improved clarity and functionality ([4ff2465](https://github.com/decentralized-identity/didwebvh-ts/commit/4ff24652887d1c8c03f12af6ab4814051835b7f5))

# [2.1.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.0.2...v2.1.0) (2025-05-23)


### Features

* add @noble/hashes dependency and refactor createHash function to use it ([4527738](https://github.com/decentralized-identity/didwebvh-ts/commit/45277380d9ea9bafd6d581e9fb123002f6be3795))

## [2.0.2](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.0.1...v2.0.2) (2025-05-23)


### Bug Fixes

* update getFileUrl to use domain end index for URL construction ([b4aa3af](https://github.com/decentralized-identity/didwebvh-ts/commit/b4aa3af9e96a5ebae0a20fafab711f6ff261809f))

## [2.0.1](https://github.com/decentralized-identity/didwebvh-ts/compare/v2.0.0...v2.0.1) (2025-04-25)


### Bug Fixes

* export resolveDIDFromLog ([eace3c8](https://github.com/decentralized-identity/didwebvh-ts/commit/eace3c82e2a72fe3e38e2ae7aa69b6e47f113d70))

# [2.0.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v1.1.0...v2.0.0) (2025-03-24)


### chore

* Bump version ([377f423](https://github.com/decentralized-identity/didwebvh-ts/commit/377f4237ab5b79119d410d54f33b89b0307e007b))


### BREAKING CHANGES

* see previous

# [1.1.0](https://github.com/decentralized-identity/didwebvh-ts/compare/v1.0.3...v1.1.0) (2025-03-24)


### Bug Fixes

* check SCID in DID matches log ([2590811](https://github.com/decentralized-identity/didwebvh-ts/commit/259081152b25960dd54ce3201a60e1fc7d7822db))
* remove multiformats dep ([974224b](https://github.com/decentralized-identity/didwebvh-ts/commit/974224b5b1df23701f049b9926e73af66a28e9ba))
* remove server ([2689012](https://github.com/decentralized-identity/didwebvh-ts/commit/2689012f81a547a8ac205ab9310af88ccf6d13ba))


### Features

* add Elysia and Express resolver examples with Ed25519 verification ([ea0b5fa](https://github.com/decentralized-identity/didwebvh-ts/commit/ea0b5fa6c8bf4b447e29e0554063f07d762e7ad5))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-03-24

### Added
- New `Signer` interface for implementing custom signing logic
- New `AbstractCrypto` class for easier signer implementation
- New `SigningInput` and `SigningOutput` interfaces
- New `SignerOptions` interface for configuring signers
- New `createDocumentSigner` function for creating document signers
- New example implementations in `src/examples`
  - `elysia-signer.ts`: Example using `AbstractCrypto`
  - `express-signer.ts`: Example implementing `Verifier` directly for HSM/KMS integration

### Changed
- Removed built-in cryptographic implementations
- Made cryptographic functionality injectable through the `Signer` interface
- Improved documentation and examples

### Deprecated
- `createSigner` function - use `createDocumentSigner` with your own `Signer` implementation instead
- `generateEd25519VerificationMethod` - implement your own key generation logic
- `generateX25519VerificationMethod` - implement your own key generation logic

### Removed
- `@noble/ed25519` dependency
- `@noble/curves` dependency
- Built-in Ed25519 signing implementation
- Built-in key generation logic

### Security
- Users now have full control over cryptographic implementations
- Better support for HSM and KMS integrations
- Improved key management flexibility


## [1.0.3](https://github.com/decentralized-identity/didwebvh-ts/compare/v1.0.2...v1.0.3) (2025-02-10)


### Bug Fixes

* remove build crypto inject ([2d8c184](https://github.com/decentralized-identity/didwebvh-ts/commit/2d8c1846978131a56ff42eae45950c8163357374))

## [1.0.2](https://github.com/decentralized-identity/didwebvh-ts/compare/v1.0.1...v1.0.2) (2025-01-27)


### Bug Fixes

* bump version ([8194920](https://github.com/decentralized-identity/didwebvh-ts/commit/8194920f290a46857c8bb82a720b46fe6211baf1))

# 1.0.0 (2025-01-27)


### Bug Fixes

* add github app to publish workflow ([59fc55a](https://github.com/decentralized-identity/didwebvh-ts/commit/59fc55a2568067d7eba952d9ac51adc29f7299db))
* Fix release workflow ([2b429b4](https://github.com/decentralized-identity/didwebvh-ts/commit/2b429b4dcd52d1ebe9c9744a5903272ed4c406bb))
* include dist folder recursively in publish ([f7b1cd5](https://github.com/decentralized-identity/didwebvh-ts/commit/f7b1cd514aa99b25f7bd2466283f95afa55ab9d1))
* **package:** fix name ([e33ce21](https://github.com/decentralized-identity/didwebvh-ts/commit/e33ce2146615bc2fd2d300a425176e83acf334cd))
* proper branch name for publish action ([ce39b9b](https://github.com/decentralized-identity/didwebvh-ts/commit/ce39b9b3b26ec49269f261a9a9fb8305d95872c8))
* proper semantic release branch config ([343eec7](https://github.com/decentralized-identity/didwebvh-ts/commit/343eec76575deab7d579e6e8844128627ea70660))
* release branch instead of main ([42db471](https://github.com/decentralized-identity/didwebvh-ts/commit/42db471500e4317b8442b808ae0cf3162599f040))
* release config for semantic-release tool ([3f59d12](https://github.com/decentralized-identity/didwebvh-ts/commit/3f59d12ec1130967c345d27549506e4625a9d386))
* releaserc.js file to module ([e750e7a](https://github.com/decentralized-identity/didwebvh-ts/commit/e750e7a3391c3e1e2fdb024b96bb1f56ff16bd0b))
* trigger release ([2b4c1db](https://github.com/decentralized-identity/didwebvh-ts/commit/2b4c1db7e10c558b56a9e70eea8290c72d5d1c0e))
* try forcing last release ([5b3360c](https://github.com/decentralized-identity/didwebvh-ts/commit/5b3360c5eedc1cf2abed5070cf0635a428b4ebed))


### Features

* add npm release ([8903f8d](https://github.com/decentralized-identity/didwebvh-ts/commit/8903f8d4edebc1cc7fe9c04e4c2b8d9ade12c1a3))
* minor version bump ([0751250](https://github.com/decentralized-identity/didwebvh-ts/commit/0751250d006cc9c085d78ba66091f05d576f02f8))

# @interop/did-method-webvh Changelog

## 0.1.0 - 2025-01-10

### Updated
- Rename `tdw` to `webvh`.

## 0.0.2 - 2024-04-04

### Added
- Add `options` to resolveDID.
  - Option `versionId` to query specific version.
  - Option `versionTime` to query specific time.

## 0.0.1 - 2024-04-02

### Added
- Add initial files.
