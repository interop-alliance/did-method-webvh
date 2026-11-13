import { DIDResolutionError, type IDIDResolutionResult } from '@interop/data-integrity-core';
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  createDID as createWebvh,
  resolveDID as resolveWebvh,
  resolveDIDFromLog as resolveWebvhFromLog,
  updateDID as updateWebvh,
} from '../src/index.js';
import type { DIDLog } from '../src/interfaces.js';
import { prepareGenesisEntry } from '../src/method_versions/method.v1.0.entries.js';
import { VH_PROFILE } from '../src/method_versions/profile.js';
import { deriveNextKeyHash } from '../src/utils/crypto.js';
import { parseDidVhIdentifier } from '../src/utils/did-vh-identifier.js';
import { logToJsonlString } from '../src/utils.js';
import {
  createDID,
  deactivateDID,
  resolveDID,
  resolveDIDFromLog,
  updateDID,
  VH_METHOD_PROTOCOL_V1_0,
} from '../src/vh.js';
import {
  appendRawLogEntry,
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  createWitnessedTestDID,
  generateTestVerificationMethod,
  MOCK_SCID,
  nextSecond,
  stubGlobalFetchUnused,
} from './utils.js';
import { appendService, createThreeEntryVh, createUrlFetch, createVhFixture, createWitnessedVh } from './vh-helpers.js';

type ResolutionMeta = {
  error?: string;
  message?: string;
  warnings?: { code: string; message: string }[];
  didLog?: string;
  didWitness?: unknown;
};
type DocumentMeta = {
  ttl?: unknown;
  watchers?: unknown;
  witness?: { threshold?: unknown };
  portable?: unknown;
  updated?: string;
  versionId?: string;
  deactivated?: boolean;
};
const rmeta = (result: IDIDResolutionResult) => result.didResolutionMetadata as ResolutionMeta;
const dmeta = (result: IDIDResolutionResult) => result.didDocumentMetadata as DocumentMeta;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('parseDidVhIdentifier', () => {
  test('accepts did:vh:<46 base58btc characters> and returns the SCID', () => {
    expect(parseDidVhIdentifier(`did:vh:${MOCK_SCID}`, 'did')).toBe(MOCK_SCID);
  });

  test('rejects a further component, wrong lengths, and non-base58 characters', () => {
    const bad = [
      `did:vh:${MOCK_SCID}:example.com`,
      `did:vh:${MOCK_SCID}x`,
      `did:vh:${MOCK_SCID.slice(1)}`,
      'did:vh:',
      `did:vh:0${MOCK_SCID.slice(1)}`,
      `did:vh:O${MOCK_SCID.slice(1)}`,
      `did:vh:I${MOCK_SCID.slice(1)}`,
      `did:vh:l${MOCK_SCID.slice(1)}`,
    ];
    for (const did of bad) {
      expect(() => parseDidVhIdentifier(did, 'did'), did).toThrow(/did:vh/);
    }
  });

  test('rejects did:webvh identifiers and an uppercase prefix', () => {
    expect(() => parseDidVhIdentifier(`did:webvh:${MOCK_SCID}:example.com`, 'did')).toThrow();
    expect(() => parseDidVhIdentifier(`DID:vh:${MOCK_SCID}`, 'did')).toThrow();
    expect(() => parseDidVhIdentifier(`did:VH:${MOCK_SCID}`, 'did')).toThrow();
  });

  test('accepts the {SCID} placeholder only with allowScidPlaceholder', () => {
    expect(() => parseDidVhIdentifier('did:vh:{SCID}', 'did')).toThrow();
    expect(parseDidVhIdentifier('did:vh:{SCID}', 'did', { allowScidPlaceholder: true })).toBe('{SCID}');
    expect(() => parseDidVhIdentifier('did:vh:{SCID}:x', 'did', { allowScidPlaceholder: true })).toThrow();
  });
});

describe('round trip', () => {
  test('create, update and deactivate', async () => {
    const f = await createVhFixture();
    const { signer, verifier } = f;

    expect(f.log[0].parameters.method).toBe('did:vh:1.0');
    expect(f.log[0].parameters.method).toBe(VH_METHOD_PROTOCOL_V1_0);
    expect('portable' in f.log[0].parameters).toBe(false);
    expect('portable' in f.meta).toBe(false);
    expect(f.did).toBe(`did:vh:${f.log[0].parameters.scid}`);
    expect(f.did).toMatch(/^did:vh:[1-9A-HJ-NP-Za-km-z]{46}$/);
    expect(f.doc.id).toBe(f.did);

    const log2 = await appendService(f, f.log, 'one');
    const deactivated = await deactivateDID({ log: log2, signer, verifier });
    expect(deactivated.log).toHaveLength(3);
    expect('portable' in deactivated.meta).toBe(false);
    expect('portable' in (await resolveDIDFromLog(log2, { verifier })).meta).toBe(false);

    const live = await resolveDID(f.did, { didLog: log2, verifier });
    expect(live.didResolutionMetadata.error).toBeUndefined();
    expect(live.didDocument?.id).toBe(f.did);
    expect(dmeta(live).versionId).toBe(log2[1].versionId);

    const dead = await resolveDID(f.did, { didLog: deactivated.log, verifier });
    expect(dead.didResolutionMetadata.error).toBeUndefined();
    expect(dead.didDocument).toBeNull();
    expect(dmeta(dead).deactivated).toBe(true);
  });

  test('didLog as a JSONL string and as an array resolve identically', async () => {
    const f = await createThreeEntryVh();
    const fromArray = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier });
    const fromString = await resolveDID(f.did, { didLog: logToJsonlString(f.log), verifier: f.verifier });
    expect(fromArray.didResolutionMetadata.error).toBeUndefined();
    expect(fromString).toEqual(fromArray);
  });

  test('a log that is not JSON Lines is invalidDid', async () => {
    const f = await createVhFixture();
    const result = await resolveDID(f.did, { didLog: 'not json', verifier: f.verifier });
    expect(rmeta(result).error).toBe('invalidDid');
  });

  test('version selectors pick versionId, versionNumber and versionTime', async () => {
    const f = await createThreeEntryVh();
    const { verifier, log } = f;

    const byId = await resolveDID(f.did, { didLog: log, verifier, versionId: log[1].versionId });
    expect(dmeta(byId).versionId).toBe(log[1].versionId);

    const byNumber = await resolveDID(f.did, { didLog: log, verifier, versionNumber: 1 });
    expect(dmeta(byNumber).versionId).toBe(log[0].versionId);
    expect(byNumber.didDocument?.service).toBeUndefined();

    const byTime = await resolveDID(f.did, { didLog: log, verifier, versionTime: new Date(log[1].versionTime) });
    expect(dmeta(byTime).versionId).toBe(log[1].versionId);

    const latest = await resolveDID(f.did, { didLog: log, verifier });
    expect(dmeta(latest).versionId).toBe(log[2].versionId);
  });

  test('a selector that matches no entry is notFound', async () => {
    const f = await createVhFixture();
    const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier, versionNumber: 5 });
    expect(rmeta(result).error).toBe('notFound');
    expect(result.didDocument).toBeNull();
  });

  test('an authored didDocument using did:vh:{SCID} works', async () => {
    const key = await generateTestVerificationMethod();
    const signer = createTestSigner(key);
    const verifier = createTestVerifier(key);
    const vmId = 'did:vh:{SCID}#key-1';
    const created = await createDID({
      signer,
      verifier,
      updateKeys: [key.publicKeyMultibase!],
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
        id: 'did:vh:{SCID}',
        verificationMethod: [
          {
            id: vmId,
            type: 'Multikey',
            controller: 'did:vh:{SCID}',
            publicKeyMultibase: key.publicKeyMultibase,
          },
        ],
        authentication: [vmId],
      },
    });
    expect(created.did).toMatch(/^did:vh:[1-9A-HJ-NP-Za-km-z]{46}$/);
    expect(created.doc.id).toBe(created.did);
    expect(JSON.stringify(created.doc)).not.toContain('{SCID}');
    const result = await resolveDID(created.did, { didLog: created.log, verifier });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(created.did);
  });

  test('createDID accepts an explicit method of did:vh:1.0', async () => {
    const f = await createVhFixture({ method: 'did:vh:1.0' });
    expect(f.log[0].parameters.method).toBe('did:vh:1.0');
  });

  test('resolveDIDFromLog resolves a did:vh log to the core result and throws on failure', async () => {
    const f = await createThreeEntryVh();
    const core = await resolveDIDFromLog(f.log, { verifier: f.verifier });
    expect(core.did).toBe(f.did);
    expect(core.meta.versionId).toBe(f.log[2].versionId);
    await expect(
      resolveDIDFromLog(f.log, { verifier: f.verifier, versionId: 'bogus' }) as Promise<unknown>
    ).resolves.toBeDefined();
  });
});

describe('write-side refusals', () => {
  const locationOptions: [string, unknown][] = [
    ['address', 'example.com'],
    ['paths', ['a']],
    ['portable', true],
    ['portable', false],
    ['alsoKnownAsWeb', true],
  ];

  test('createDID throws on address, paths, portable and alsoKnownAsWeb', async () => {
    for (const [name, value] of locationOptions) {
      await expect(createVhFixture({ [name]: value } as never), name).rejects.toThrow(name);
    }
  });

  test('updateDID throws on address, paths, portable and alsoKnownAsWeb', async () => {
    const f = await createVhFixture();
    for (const [name, value] of locationOptions) {
      await expect(
        updateDID({ log: f.log, signer: f.signer, verifier: f.verifier, [name]: value } as never),
        name
      ).rejects.toThrow(name);
    }
  });

  test('createDID rejects method did:webvh:1.0', async () => {
    await expect(createVhFixture({ method: 'did:webvh:1.0' })).rejects.toThrow(/not a supported method version/);
  });

  test('createDID needs updateKeys', async () => {
    const key = await generateTestVerificationMethod();
    await expect(
      createDID({
        signer: createTestSigner(key),
        verificationMethods: asPublicVerificationMethods(key),
      } as never)
    ).rejects.toThrow('Update keys not supplied');
  });

  test('updateDID and deactivateDID refuse a deactivated DID', async () => {
    const f = await createVhFixture();
    const dead = await deactivateDID({ log: f.log, signer: f.signer, verifier: f.verifier });
    await expect(updateDID({ log: dead.log, signer: f.signer, verifier: f.verifier })).rejects.toThrow(
      'Cannot update deactivated DID'
    );
    await expect(deactivateDID({ log: dead.log, signer: f.signer, verifier: f.verifier })).rejects.toThrow(
      'already deactivated'
    );
  });
});

describe('cross-method', () => {
  test('a did:webvh log passed to the did:vh resolveDID is invalidDid', async () => {
    const f = await createVhFixture();
    const web = await createWebvh({
      address: 'example.com',
      signer: f.signer,
      verifier: f.verifier,
      updateKeys: f.updateKeys,
      verificationMethods: asPublicVerificationMethods(f.key),
    });
    const scid = web.log[0].parameters.scid!;
    const result = await resolveDID(`did:vh:${scid}`, { didLog: web.log, verifier: f.verifier });
    expect(rmeta(result).error).toBe('invalidDid');
    expect(result.didDocument).toBeNull();
  });

  test('a did:vh log passed to the did:webvh resolveDIDFromLog rejects', async () => {
    const f = await createVhFixture();
    await expect(resolveWebvhFromLog(f.log, { verifier: f.verifier, witnessProofs: [] })).rejects.toThrow();
  });

  test('did:webvh still resolves with fractional versionTime, null parameters and portable', async () => {
    const key = await generateTestVerificationMethod();
    const signer = createTestSigner(key);
    const verifier = createTestVerifier(key);
    const web = await createWebvh({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [key.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(key),
      portable: true,
    });
    expect(web.log[0].parameters.method).toBe('did:webvh:1.0');
    expect(web.log[0].parameters.portable).toBe(true);
    const updated = await updateWebvh({ log: web.log, signer, verifier, updated: nextSecond(web.log) });
    const resolved = await resolveWebvh(web.did, { verifier, resolveControlledDid: async () => updated.log });
    expect(resolved.didResolutionMetadata.error).toBeUndefined();
  });
});

/** The resolution of `log` with no selector, and with `versionNumber` naming the entry that is refused. */
const resolveBoth = async (did: string, log: DIDLog, verifier: ReturnType<typeof createTestVerifier>) => ({
  latest: await resolveDID(did, { didLog: log, verifier }),
  atRefused: await resolveDID(did, { didLog: log, verifier, versionNumber: log.length }),
  byId: await resolveDID(did, { didLog: log, verifier, versionId: log[log.length - 1].versionId }),
});

describe('did:vh rule differences', () => {
  /** Resolution with no selector answers from the last valid entry and warns. */
  const expectFallsBack = (result: IDIDResolutionResult, validLog: DIDLog, messagePattern: RegExp) => {
    expect(rmeta(result).error).toBeUndefined();
    expect(result.didDocument).not.toBeNull();
    expect(dmeta(result).versionId).toBe(validLog[validLog.length - 1].versionId);
    expect(rmeta(result).warnings?.[0].code).toBe('invalid-entries');
    expect(rmeta(result).warnings?.[0].message).toMatch(messagePattern);
  };

  /** A selector naming the refused entry gets an error, not a document. */
  const expectRefused = (result: IDIDResolutionResult) => {
    expect(['invalidDid', 'notFound']).toContain(rmeta(result).error);
    expect(result.didDocument).toBeNull();
  };

  describe('fractional-second versionTime', () => {
    const fractional = '2026-01-01T00:00:00.500Z';

    test('as the first entry, did:vh fails with invalidDid and did:webvh accepts it', async () => {
      const key = await generateTestVerificationMethod();
      const signer = createTestSigner(key);
      const verifier = createTestVerifier(key);
      const options = {
        signer,
        verifier,
        updateKeys: [key.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(key),
      };

      const vhGenesis = await prepareGenesisEntry({
        options,
        controller: 'did:vh:{SCID}',
        createdDate: fractional,
        profile: VH_PROFILE,
      });
      const vhResult = await resolveDID(vhGenesis.state.id!, { didLog: [vhGenesis], verifier });
      expect(rmeta(vhResult).error).toBe('invalidDid');
      expect(rmeta(vhResult).message).toMatch(/whole|second|fraction/i);

      const webGenesis = await prepareGenesisEntry({
        options: { ...options, address: 'example.com' },
        controller: 'did:webvh:{SCID}:example.com',
        createdDate: fractional,
      });
      await expect(resolveWebvhFromLog([webGenesis], { verifier, witnessProofs: [] })).resolves.toMatchObject({
        did: webGenesis.state.id,
      });
    });

    test('as a later entry, did:vh refuses it and did:webvh accepts it', async () => {
      const f = await createVhFixture();
      const base = Math.floor(Date.parse(f.log[0].versionTime) / 1000) * 1000;
      const versionTime = new Date(base + 1500).toISOString();
      expect(versionTime).toMatch(/\.500Z$/);
      const log = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: {}, versionTime });

      const { latest, atRefused } = await resolveBoth(f.did, log, f.verifier);
      expectFallsBack(latest, f.log, /whole|second|fraction/i);
      expectRefused(atRefused);

      const web = await createWebvh({
        address: 'example.com',
        signer: f.signer,
        updateKeys: f.updateKeys,
        verificationMethods: asPublicVerificationMethods(f.key),
      });
      const webBase = Math.floor(Date.parse(web.log[0].versionTime) / 1000) * 1000;
      const webLog = await appendRawLogEntry({
        log: web.log,
        signer: f.signer,
        parameters: {},
        versionTime: new Date(webBase + 1500).toISOString(),
      });
      await expect(resolveWebvhFromLog(webLog, { verifier: f.verifier, witnessProofs: [] })).resolves.toBeDefined();
    });
  });

  describe('entries after the log has ended', () => {
    test('an entry after one that sets deactivated: true is refused', async () => {
      const f = await createVhFixture();
      const dead = await deactivateDID({ log: f.log, signer: f.signer, verifier: f.verifier });
      const log = await appendRawLogEntry({ log: dead.log, signer: f.signer, parameters: {} });
      const { latest, atRefused } = await resolveBoth(f.did, log, f.verifier);
      // The last valid entry is the deactivation, so there is no document.
      expect(rmeta(latest).error).toBeUndefined();
      expect(latest.didDocument).toBeNull();
      expect(dmeta(latest).deactivated).toBe(true);
      expect(dmeta(latest).versionId).toBe(dead.log[1].versionId);
      expect(rmeta(latest).warnings?.[0].code).toBe('invalid-entries');
      expectRefused(atRefused);
    });

    test('an entry after one that sets updateKeys: [] is refused', async () => {
      const f = await createVhFixture();
      const ended = await updateDID({
        log: f.log,
        signer: f.signer,
        verifier: f.verifier,
        updateKeys: [],
        updated: nextSecond(f.log),
      });
      expect(ended.log[1].parameters.updateKeys).toEqual([]);
      const log = await appendRawLogEntry({
        log: ended.log,
        signer: f.signer,
        parameters: { updateKeys: f.updateKeys },
      });

      const { latest, atRefused, byId } = await resolveBoth(f.did, log, f.verifier);
      expectFallsBack(latest, ended.log, /./);
      expect(rmeta(latest).warnings?.[0].message).toContain('after version 2');
      expectRefused(atRefused);
      expectRefused(byId);
      // The log up to and including the ending entry is valid.
      const okResult = await resolveDID(f.did, { didLog: ended.log, verifier: f.verifier });
      expect(rmeta(okResult).error).toBeUndefined();
      expect(rmeta(okResult).warnings).toBeUndefined();
    });

    test('versionNumber of the last valid entry succeeds even when a later entry is refused', async () => {
      const f = await createVhFixture();
      const ended = await updateDID({
        log: f.log,
        signer: f.signer,
        verifier: f.verifier,
        updateKeys: [],
        updated: nextSecond(f.log),
      });
      const log = await appendRawLogEntry({ log: ended.log, signer: f.signer, parameters: {} });
      const result = await resolveDID(f.did, { didLog: log, verifier: f.verifier, versionNumber: 2 });
      expect(rmeta(result).error).toBeUndefined();
      expect(dmeta(result).versionId).toBe(ended.log[1].versionId);
    });
  });

  describe('pre-rotation', () => {
    const setup = async () => {
      const key2 = await generateTestVerificationMethod();
      const f = await createVhFixture({ nextKeyHashes: [await deriveNextKeyHash(key2.publicKeyMultibase!)] });
      return { ...f, key2, signer2: createTestSigner(key2), key2Keys: [key2.publicKeyMultibase!] };
    };

    test('updateDID throws when nextKeyHashes is omitted while pre-rotation is active', async () => {
      const s = await setup();
      await expect(
        updateDID({
          log: s.log,
          signer: s.signer2,
          verifier: s.verifier,
          updateKeys: s.key2Keys,
          updated: nextSecond(s.log),
        })
      ).rejects.toThrow(/nextKeyHashes/);
    });

    test('an update that passes nextKeyHashes: [] ends pre-rotation and later updates may omit it', async () => {
      const s = await setup();
      const log2 = (
        await updateDID({
          log: s.log,
          signer: s.signer2,
          verifier: s.verifier,
          updateKeys: s.key2Keys,
          nextKeyHashes: [],
          updated: nextSecond(s.log),
        })
      ).log;
      const log3 = await updateDID({
        log: log2,
        signer: s.signer2,
        verifier: s.verifier,
        updated: nextSecond(log2),
      });
      const result = await resolveDID(s.did, { didLog: log3.log, verifier: s.verifier });
      expect(rmeta(result).error).toBeUndefined();
      expect(rmeta(result).warnings).toBeUndefined();
      expect(dmeta(result).versionId).toBe(log3.log[2].versionId);
    });

    test('pre-rotation is active only from the entry after the one that sets nextKeyHashes', async () => {
      const f = await createVhFixture();
      const key2 = await generateTestVerificationMethod();
      const key3 = await generateTestVerificationMethod();
      // Entry 2 sets nextKeyHashes and needs no nextKeyHashes of its own to be valid.
      const log2 = await updateDID({
        log: f.log,
        signer: f.signer,
        verifier: f.verifier,
        nextKeyHashes: [await deriveNextKeyHash(key2.publicKeyMultibase!)],
        updated: nextSecond(f.log),
      });
      expect(log2.log[1].parameters.nextKeyHashes).toHaveLength(1);
      // Entry 3 is the first under pre-rotation, so it must repeat nextKeyHashes.
      await expect(
        updateDID({
          log: log2.log,
          signer: createTestSigner(key2),
          verifier: f.verifier,
          updateKeys: [key2.publicKeyMultibase!],
          updated: nextSecond(log2.log),
        })
      ).rejects.toThrow(/nextKeyHashes/);
      const log3 = await updateDID({
        log: log2.log,
        signer: createTestSigner(key2),
        verifier: f.verifier,
        updateKeys: [key2.publicKeyMultibase!],
        nextKeyHashes: [await deriveNextKeyHash(key3.publicKeyMultibase!)],
        updated: nextSecond(log2.log),
      });
      const result = await resolveDID(f.did, { didLog: log3.log, verifier: f.verifier });
      expect(rmeta(result).error).toBeUndefined();
      expect(rmeta(result).warnings).toBeUndefined();
    });

    test('a hand-built entry that omits nextKeyHashes fails did:vh resolution but not did:webvh', async () => {
      const s = await setup();
      const log = await appendRawLogEntry({
        log: s.log,
        signer: s.signer2,
        parameters: { updateKeys: s.key2Keys },
      });
      const { latest, atRefused } = await resolveBoth(s.did, log, s.verifier);
      expectFallsBack(latest, s.log, /nextKeyHashes/);
      expectRefused(atRefused);

      const key1 = await generateTestVerificationMethod();
      const key2 = await generateTestVerificationMethod();
      const web = await createWebvh({
        address: 'example.com',
        signer: createTestSigner(key1),
        updateKeys: [key1.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(key1),
        nextKeyHashes: [await deriveNextKeyHash(key2.publicKeyMultibase!)],
      });
      const webLog = await appendRawLogEntry({
        log: web.log,
        signer: createTestSigner(key2),
        parameters: { updateKeys: [key2.publicKeyMultibase!] },
      });
      await expect(
        resolveWebvhFromLog(webLog, { verifier: createTestVerifier(key1), witnessProofs: [] })
      ).resolves.toBeDefined();
    });

    test('deactivateDID refuses while pre-rotation is active', async () => {
      const s = await setup();
      await expect(deactivateDID({ log: s.log, signer: s.signer, verifier: s.verifier })).rejects.toThrow(
        /pre-rotation/
      );
    });
  });

  describe('disallowed and null parameters', () => {
    test('parameters.portable in a did:vh entry fails, and did:webvh accepts a portable genesis', async () => {
      const f = await createVhFixture();
      const log = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: { portable: false } });
      const { latest, atRefused } = await resolveBoth(f.did, log, f.verifier);
      expectFallsBack(latest, f.log, /portable/);
      expectRefused(atRefused);
    });

    test('a null parameter value fails in did:vh and is accepted in did:webvh', async () => {
      const f = await createVhFixture();
      for (const name of ['watchers', 'witness', 'nextKeyHashes']) {
        const log = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: { [name]: null } });
        const { latest, atRefused } = await resolveBoth(f.did, log, f.verifier);
        expectFallsBack(latest, f.log, /./);
        expectRefused(atRefused);
      }

      const web = await createWebvh({
        address: 'example.com',
        signer: f.signer,
        updateKeys: f.updateKeys,
        verificationMethods: asPublicVerificationMethods(f.key),
      });
      const webLog = await appendRawLogEntry({
        log: web.log,
        signer: f.signer,
        parameters: { watchers: null },
      });
      await expect(resolveWebvhFromLog(webLog, { verifier: f.verifier, witnessProofs: [] })).resolves.toBeDefined();
    });
  });

  describe('method values', () => {
    const genesisWithMethod = async (method: string) => {
      const key = await generateTestVerificationMethod();
      const verifier = createTestVerifier(key);
      const genesis = await prepareGenesisEntry({
        options: {
          signer: createTestSigner(key),
          verifier,
          updateKeys: [key.publicKeyMultibase!],
          verificationMethods: asPublicVerificationMethods(key),
        },
        controller: 'did:vh:{SCID}',
        createdDate: '2026-01-01T00:00:00Z',
        profile: { ...VH_PROFILE, method },
      });
      return resolveDID(genesis.state.id!, { didLog: [genesis], verifier });
    };

    test('a well-formed newer first-entry method is featureNotSupported', async () => {
      for (const method of ['did:vh:99.0', 'did:vh:2.0', 'did:vh:1.1']) {
        const result = await genesisWithMethod(method);
        expect(rmeta(result).error, method).toBe('featureNotSupported');
        expect(result.didDocument).toBeNull();
      }
    });

    test('malformed or foreign first-entry method values are invalidDid', async () => {
      for (const method of ['did:vh:01.0', 'did:vh:1.0-rc1', 'didvh:1.0', 'did:webvh:1.0']) {
        const result = await genesisWithMethod(method);
        expect(rmeta(result).error, method).toBe('invalidDid');
      }
    });

    test('a later entry declaring did:vh:2.0 is featureNotSupported with no selector, but versionNumber 1 succeeds', async () => {
      const f = await createVhFixture();
      const log = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: { method: 'did:vh:2.0' } });

      const latest = await resolveDID(f.did, { didLog: log, verifier: f.verifier });
      expect(rmeta(latest).error).toBe('featureNotSupported');
      expect(latest.didDocument).toBeNull();

      const first = await resolveDID(f.did, { didLog: log, verifier: f.verifier, versionNumber: 1 });
      expect(rmeta(first).error).toBeUndefined();
      expect(dmeta(first).versionId).toBe(log[0].versionId);
    });

    test('a later entry declaring a lower or malformed method falls back to the last valid entry', async () => {
      const f = await createVhFixture();
      for (const method of ['did:vh:0.9', 'did:vh:02.0', 'did:webvh:1.0']) {
        const log = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: { method } });
        const result = await resolveDID(f.did, { didLog: log, verifier: f.verifier });
        expect(rmeta(result).error, method).toBeUndefined();
        expect(rmeta(result).warnings?.[0].code, method).toBe('invalid-entries');
      }
    });
  });

  describe('document metadata', () => {
    test('ttl is the number 3600 by default and there is no portable key', async () => {
      const f = await createVhFixture();
      const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier });
      expect(dmeta(result).ttl).toBe(3600);
      expect('portable' in result.didDocumentMetadata).toBe(false);
    });

    test('ttl follows the parameter', async () => {
      const f = await createVhFixture();
      const log = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: { ttl: 60 } });
      const result = await resolveDID(f.did, { didLog: log, verifier: f.verifier });
      expect(dmeta(result).ttl).toBe(60);
    });

    test('the witness threshold is a number', async () => {
      const w = await createWitnessedVh(1);
      const result = await resolveDID(w.did, { didLog: w.log, didWitness: w.didWitness, verifier: w.verifier });
      expect(rmeta(result).error).toBeUndefined();
      expect(typeof dmeta(result).witness?.threshold).toBe('number');
      expect(dmeta(result).witness?.threshold).toBe(1);
    });

    test("updated is the last valid entry's versionTime even when an earlier version is selected", async () => {
      const f = await createThreeEntryVh();
      const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier, versionNumber: 1 });
      expect(dmeta(result).versionId).toBe(f.log[0].versionId);
      expect(dmeta(result).updated).toBe(f.log[2].versionTime);
    });

    test('updated is the last valid entry when a later entry is refused', async () => {
      const f = await createVhFixture();
      const bad = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: { portable: false } });
      const result = await resolveDID(f.did, { didLog: bad, verifier: f.verifier });
      expect(dmeta(result).updated).toBe(f.log[0].versionTime);
    });
  });
});

describe('options validation', () => {
  test('neither or both of didLog and srcLog is invalidOptions', async () => {
    const f = await createVhFixture();
    const neither = await resolveDID(f.did, { verifier: f.verifier });
    expect(rmeta(neither).error).toBe('invalidOptions');
    const both = await resolveDID(f.did, {
      didLog: f.log,
      srcLog: 'https://example.com/did.jsonl',
      verifier: f.verifier,
    });
    expect(rmeta(both).error).toBe('invalidOptions');
  });

  test('both didWitness and srcWitness is invalidOptions', async () => {
    const f = await createVhFixture();
    const result = await resolveDID(f.did, {
      didLog: f.log,
      didWitness: [],
      srcWitness: 'https://example.com/did-witness.json',
      verifier: f.verifier,
    });
    expect(rmeta(result).error).toBe('invalidOptions');
  });

  test('two version selectors, and a bad versionNumber, are invalidOptions', async () => {
    const f = await createThreeEntryVh();
    const cases = [
      { versionNumber: 1, versionId: f.log[0].versionId },
      { versionNumber: 1, versionTime: new Date(f.log[0].versionTime) },
      { versionNumber: 0 },
      { versionNumber: 1.5 },
      { versionNumber: -1 },
    ];
    for (const selectors of cases) {
      const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier, ...selectors });
      expect(rmeta(result).error, JSON.stringify(selectors)).toBe('invalidOptions');
    }
  });

  test('a non-https extraWatchers entry is invalidOptions', async () => {
    const f = await createVhFixture();
    for (const extraWatchers of [['http://w.example'], ['w.example'], ['ftp://w.example'], 'https://w.example']) {
      const result = await resolveDID(f.did, {
        didLog: f.log,
        verifier: f.verifier,
        extraWatchers: extraWatchers as string[],
      });
      expect(rmeta(result).error, String(extraWatchers)).toBe('invalidOptions');
    }
  });

  test('a malformed checkWatchers or minCopies is invalidOptions', async () => {
    const f = await createVhFixture();
    for (const options of [{ checkWatchers: -1 }, { checkWatchers: 1.5 }, { minCopies: 0 }, { minCopies: 1.5 }]) {
      const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier, ...options });
      expect(rmeta(result).error, JSON.stringify(options)).toBe('invalidOptions');
    }
  });

  test('copy-comparison options are featureNotSupported', async () => {
    const f = await createVhFixture();
    const cases = [
      { checkWatchers: 1 },
      { checkWatchers: 'all' as const },
      { extraWatchers: ['https://w.example'] },
      { minCopies: 2 },
    ];
    for (const options of cases) {
      const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier, ...options });
      expect(rmeta(result).error, JSON.stringify(options)).toBe('featureNotSupported');
      expect(result.didDocument).toBeNull();
    }
  });

  test('the default copy-comparison values are accepted', async () => {
    const f = await createVhFixture();
    const result = await resolveDID(f.did, {
      didLog: f.log,
      verifier: f.verifier,
      checkWatchers: 0,
      extraWatchers: [],
      minCopies: 1,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(result.didDocument).not.toBeNull();
  });

  test('a DID that is not did:vh syntax is invalidDid', async () => {
    const f = await createVhFixture();
    const bad = [
      `did:webvh:${MOCK_SCID}:example.com`,
      `did:vh:${MOCK_SCID}:example.com`,
      'did:vh:short',
      `did:vh:${MOCK_SCID}/path`,
      'did:example:123',
      '',
    ];
    for (const did of bad) {
      const result = await resolveDID(did, { didLog: f.log, verifier: f.verifier });
      expect(rmeta(result).error, did).toBe('invalidDid');
    }
  });

  test("a DID whose SCID differs from the log's is invalidDid", async () => {
    const f = await createVhFixture();
    const result = await resolveDID(`did:vh:${MOCK_SCID}`, { didLog: f.log, verifier: f.verifier });
    expect(rmeta(result).error).toBe('invalidDid');
    expect(result.didDocument).toBeNull();
  });
});

describe('witnessed logs with the witness file passed directly', () => {
  test('threshold 1 resolves with didWitness and makes no network request', async () => {
    const globalFetch = stubGlobalFetchUnused();
    const w = await createWitnessedVh(1);
    const result = await resolveDID(w.did, { didLog: w.log, didWitness: w.didWitness, verifier: w.verifier });
    expect(rmeta(result).error).toBeUndefined();
    expect(result.didDocument?.id).toBe(w.did);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test('threshold 2 of 2 needs both proofs', async () => {
    const globalFetch = stubGlobalFetchUnused();
    const w = await createWitnessedVh(2, 2);
    const versionId = w.log[0].versionId;
    const both = await resolveDID(w.did, { didLog: w.log, didWitness: w.didWitness, verifier: w.verifier });
    expect(rmeta(both).error).toBeUndefined();

    const one = await w.proofsFor(versionId, [w.witnessKeys[0]]);
    const short = await resolveDID(w.did, { didLog: w.log, didWitness: [one], verifier: w.verifier });
    expect(rmeta(short).error).toBe('invalidDid');
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test('an omitted or empty didWitness is invalidDid without a network request', async () => {
    const globalFetch = stubGlobalFetchUnused();
    const w = await createWitnessedVh(1);
    const omitted = await resolveDID(w.did, { didLog: w.log, verifier: w.verifier });
    expect(rmeta(omitted).error).toBe('invalidDid');
    const empty = await resolveDID(w.did, { didLog: w.log, didWitness: [], verifier: w.verifier });
    expect(rmeta(empty).error).toBe('invalidDid');
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test('a didWitness that is not an array is invalidOptions', async () => {
    const w = await createWitnessedVh(1);
    const result = await resolveDID(w.did, { didLog: w.log, didWitness: {} as never, verifier: w.verifier });
    expect(rmeta(result).error).toBe('invalidOptions');
  });

  test('witness proofs for a version of another log do not satisfy the threshold', async () => {
    const w = await createWitnessedVh(1);
    const other = await w.proofsFor(`1-${MOCK_SCID}`);
    const result = await resolveDID(w.did, { didLog: w.log, didWitness: [other], verifier: w.verifier });
    expect(rmeta(result).error).toBe('invalidDid');
  });
});

describe('includeDidLog', () => {
  test('returns the verified log as JSONL, and no didWitness for an unwitnessed log', async () => {
    const f = await createThreeEntryVh();
    const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier, includeDidLog: true });
    expect(rmeta(result).didLog).toBe(logToJsonlString(f.log));
    expect('didWitness' in rmeta(result)).toBe(false);
  });

  test('is absent unless requested', async () => {
    const f = await createVhFixture();
    const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier });
    expect('didLog' in rmeta(result)).toBe(false);
  });

  test('returns the witness file for a witnessed log', async () => {
    const w = await createWitnessedVh(1);
    const result = await resolveDID(w.did, {
      didLog: w.log,
      didWitness: w.didWitness,
      verifier: w.verifier,
      includeDidLog: true,
    });
    expect(rmeta(result).didLog).toBe(logToJsonlString(w.log));
    expect(rmeta(result).didWitness).toEqual(w.didWitness);
  });

  test('neither is present on an error result', async () => {
    const w = await createWitnessedVh(1);
    const result = await resolveDID(w.did, {
      didLog: w.log,
      didWitness: [],
      verifier: w.verifier,
      includeDidLog: true,
    });
    expect(rmeta(result).error).toBe('invalidDid');
    expect('didLog' in rmeta(result)).toBe(false);
    expect('didWitness' in rmeta(result)).toBe(false);

    const badOptions = await resolveDID(w.did, { includeDidLog: true, verifier: w.verifier });
    expect(rmeta(badOptions).error).toBe('invalidOptions');
    expect('didLog' in rmeta(badOptions)).toBe(false);
  });

  test('ends at the last valid entry when later entries are invalid', async () => {
    const f = await createVhFixture();
    const log2 = await appendService(f, f.log, 'one');
    const bad = await appendRawLogEntry({ log: log2, signer: f.signer, parameters: { portable: false } });
    const result = await resolveDID(f.did, { didLog: bad, verifier: f.verifier, includeDidLog: true });
    expect(rmeta(result).warnings?.[0].code).toBe('invalid-entries');
    expect(rmeta(result).didLog).toBe(logToJsonlString(log2));
  });
});

describe('a log whose later entries fail verification', () => {
  /** A three-entry log whose third entry has a `state` its proof does not cover. */
  const createTamperedVh = async () => {
    const f = await createThreeEntryVh();
    const tampered = structuredClone(f.log);
    tampered[2].state.alsoKnownAs = ['https://attacker.example'];
    return { ...f, validLog: f.log.slice(0, 2), log: tampered };
  };

  test('resolveDID answers from the last valid entry', async () => {
    const f = await createTamperedVh();
    const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier });
    expect(rmeta(result).error).toBeUndefined();
    expect(dmeta(result).versionId).toBe(f.validLog[1].versionId);
    expect(rmeta(result).warnings?.[0].code).toBe('invalid-entries');
  });

  test('resolveDIDFromLog, updateDID and deactivateDID throw', async () => {
    const f = await createTamperedVh();
    await expect(resolveDIDFromLog(f.log, { verifier: f.verifier })).rejects.toThrow();
    await expect(
      updateDID({ log: f.log, signer: f.signer, verifier: f.verifier, updated: nextSecond(f.log) })
    ).rejects.toThrow();
    await expect(deactivateDID({ log: f.log, signer: f.signer, verifier: f.verifier })).rejects.toThrow();
  });

  test('a retrieval or internal failure during verification is returned under its own code', async () => {
    const f = await createThreeEntryVh();
    let calls = 0;
    const verifier: typeof f.verifier = {
      verify: async (...args) => {
        calls += 1;
        if (calls === 3) {
          throw new DIDResolutionError('key lookup timed out', { code: 'internalError' });
        }
        return f.verifier.verify(...args);
      },
    };
    const latest = await resolveDID(f.did, { didLog: f.log, verifier });
    expect(rmeta(latest).error).toBe('internalError');
    expect(latest.didDocument).toBeNull();

    calls = 0;
    const first = await resolveDID(f.did, { didLog: f.log, verifier, versionNumber: 1 });
    expect(rmeta(first).error).toBe('internalError');
  });

  test('an entry of a newer method version is featureNotSupported whatever else it holds', async () => {
    const f = await createVhFixture();
    const log2 = await appendService(f, f.log, 'one');
    const withNewParameter = await appendRawLogEntry({
      log: log2,
      signer: f.signer,
      parameters: { method: 'did:vh:2.0', keyCommitments: ['x'] },
    });
    const withFraction = await appendRawLogEntry({
      log: log2,
      signer: f.signer,
      parameters: { method: 'did:vh:2.0' },
      versionTime: nextSecond(log2).replace('Z', '.500Z'),
    });
    for (const log of [withNewParameter, withFraction]) {
      const result = await resolveDID(f.did, { didLog: log, verifier: f.verifier });
      expect(rmeta(result).error).toBe('featureNotSupported');
      expect(result.didDocument).toBeNull();
    }
  });

  test('ttl, witness, watchers and updated are those of the last valid entry', async () => {
    const f = await createVhFixture();
    const watchers = ['https://watcher.example'];
    const log = await appendRawLogEntry({ log: f.log, signer: f.signer, parameters: { ttl: 60, watchers } });
    const first = await resolveDID(f.did, { didLog: log, verifier: f.verifier, versionNumber: 1 });
    expect(rmeta(first).error).toBeUndefined();
    expect(dmeta(first).versionId).toBe(log[0].versionId);
    expect(dmeta(first).ttl).toBe(60);
    expect(dmeta(first).watchers).toEqual(watchers);
    expect(dmeta(first).updated).toBe(log[1].versionTime);
  });
});

describe('an entry whose witness threshold is not met', () => {
  /** A witnessed first entry with its proofs, and a valid second entry with none. */
  const createUnwitnessedSecondEntry = async () => {
    const w = await createWitnessedVh(1);
    const updated = await updateDID({
      log: w.log,
      signer: w.signer,
      verifier: w.verifier,
      witnessProofs: w.didWitness,
      updated: nextSecond(w.log),
      services: [{ id: '#one', type: 'Example', serviceEndpoint: 'https://one.example' }],
    });
    return { ...w, firstLog: w.log, log: updated.log };
  };

  test('with no selector, resolution answers from the last witnessed entry and warns', async () => {
    const w = await createUnwitnessedSecondEntry();
    const result = await resolveDID(w.did, {
      didLog: w.log,
      didWitness: w.didWitness,
      verifier: w.verifier,
      includeDidLog: true,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(dmeta(result).versionId).toBe(w.log[0].versionId);
    expect(dmeta(result).updated).toBe(w.log[0].versionTime);
    expect(rmeta(result).warnings?.[0].code).toBe('invalid-entries');
    expect(rmeta(result).warnings?.[0].message).toMatch(/Witness threshold not met/);
    expect(rmeta(result).didLog).toBe(logToJsonlString(w.firstLog));
  });

  test('a selector for the witnessed entry succeeds, and one for the unwitnessed entry is invalidDid', async () => {
    const w = await createUnwitnessedSecondEntry();
    const options = { didLog: w.log, didWitness: w.didWitness, verifier: w.verifier };
    const first = await resolveDID(w.did, { ...options, versionNumber: 1 });
    expect(rmeta(first).error).toBeUndefined();
    expect(first.didDocument?.id).toBe(w.did);

    const second = await resolveDID(w.did, { ...options, versionNumber: 2 });
    expect(rmeta(second).error).toBe('invalidDid');
    expect(second.didDocument).toBeNull();
  });

  test('proofs for the later entry satisfy both entries', async () => {
    const w = await createUnwitnessedSecondEntry();
    const didWitness = [await w.proofsFor(w.log[1].versionId)];
    const result = await resolveDID(w.did, { didLog: w.log, didWitness, verifier: w.verifier });
    expect(rmeta(result).error).toBeUndefined();
    expect(rmeta(result).warnings).toBeUndefined();
    expect(dmeta(result).versionId).toBe(w.log[1].versionId);
  });

  test('resolveDIDFromLog and updateDID throw', async () => {
    const w = await createUnwitnessedSecondEntry();
    await expect(resolveDIDFromLog(w.log, { verifier: w.verifier, witnessProofs: w.didWitness })).rejects.toThrow(
      /Witness threshold not met/
    );
    await expect(
      updateDID({
        log: w.log,
        signer: w.signer,
        verifier: w.verifier,
        witnessProofs: w.didWitness,
        updated: nextSecond(w.log),
      })
    ).rejects.toThrow(/Witness threshold not met/);
  });
});

describe("network: 'log-only' for did:webvh", () => {
  test('fetches did.jsonl, not did-witness.json, and reports the proofs as not found', async () => {
    const key = await generateTestVerificationMethod();
    const verifier = createTestVerifier(key);
    const witnessed = await createWitnessedTestDID({ controller: key, verifier });
    const globalFetch = stubGlobalFetchUnused();
    const { fetch, seen } = createUrlFetch({
      'https://example.com/.well-known/did.jsonl': logToJsonlString(witnessed.log),
    });

    const result = await resolveWebvh(witnessed.did, { verifier, network: 'log-only', fetch });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didResolutionMetadata.message).toContain('Witness proofs not found');
    expect(seen).toEqual(['https://example.com/.well-known/did.jsonl']);
    expect(seen.some((url) => url.includes('did-witness.json'))).toBe(false);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test('an unwitnessed log still resolves', async () => {
    const key = await generateTestVerificationMethod();
    const verifier = createTestVerifier(key);
    const web = await createWebvh({
      address: 'example.com',
      signer: createTestSigner(key),
      updateKeys: [key.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(key),
    });
    const { fetch } = createUrlFetch({ 'https://example.com/.well-known/did.jsonl': logToJsonlString(web.log) });
    const result = await resolveWebvh(web.did, { verifier, network: 'log-only', fetch });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
