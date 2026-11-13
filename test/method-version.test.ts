import { describe, expect, test } from 'vitest';
import type { DIDLog } from '../src/interfaces.js';
import { resolveDIDFromLog, updateDID } from '../src/method.js';
import { appendRawLogEntry, createTestDID } from './utils.js';

describe('parameters not defined by did:webvh:1.0', () => {
  const setup = () => createTestDID({ created: '2026-01-01T00:00:00Z' });

  test('a later entry with an undefined parameter is rejected by resolution and by updateDID', async () => {
    const { signer, verifier, log: genesis } = await setup();
    const log = await appendRawLogEntry({
      log: genesis,
      signer,
      parameters: { prerotation: true },
      versionTime: '2026-01-01T00:00:01Z',
    });
    const message = "version '2' has unsupported parameter 'prerotation'; it is not defined by did:webvh:1.0";

    await expect(resolveDIDFromLog(log, { verifier, witnessProofs: [] })).rejects.toThrow(message);
    await expect(updateDID({ log, signer, verifier, witnessProofs: [] })).rejects.toThrow(message);
  });

  test('a genesis entry with an undefined parameter is rejected before its hash is checked', async () => {
    const { verifier, log } = await setup();
    const tampered: DIDLog = [
      { ...log[0], parameters: { ...log[0].parameters, foo: 'bar' } as DIDLog[0]['parameters'] },
    ];

    await expect(resolveDIDFromLog(tampered, { verifier, witnessProofs: [] })).rejects.toThrow(
      "version '1' has unsupported parameter 'foo'; it is not defined by did:webvh:1.0"
    );
  });

  test('a later entry whose parameters is not an object is rejected', async () => {
    const { signer, verifier, log: genesis } = await setup();
    const log = await appendRawLogEntry({
      log: genesis,
      signer,
      parameters: {},
      versionTime: '2026-01-01T00:00:01Z',
    });
    for (const parameters of [['method'], null, 'method']) {
      const tampered = [log[0], { ...log[1], parameters }] as unknown as DIDLog;
      await expect(resolveDIDFromLog(tampered, { verifier, witnessProofs: [] }), String(parameters)).rejects.toThrow(
        "version '2' parameters must be a JSON object"
      );
    }
  });

  test('every parameter did:webvh:1.0 defines is accepted', async () => {
    const { signer, verifier, log: genesis } = await setup();
    const log = await appendRawLogEntry({
      log: genesis,
      signer,
      parameters: { method: 'did:webvh:1.0', portable: false, watchers: [], ttl: 600 },
      versionTime: '2026-01-01T00:00:01Z',
    });

    const resolved = await resolveDIDFromLog(log, { verifier, witnessProofs: [] });
    expect(resolved.doc).not.toBeNull();
    expect(resolved.meta.ttl).toBe(600);
  });

  test('a parameter whose value has the wrong JSON type is rejected', async () => {
    const { signer, verifier, log: genesis } = await setup();
    const cases: [Record<string, unknown>, string][] = [
      [{ watchers: 'x' }, "parameter 'watchers' must be an array of strings"],
      [{ watchers: [1] }, "parameter 'watchers' must be an array of strings"],
      [{ portable: 'yes' }, "parameter 'portable' must be a boolean"],
      [{ deactivated: 'true' }, "parameter 'deactivated' must be a boolean"],
      [{ witness: 'abc' }, "parameter 'witness' must be a JSON object"],
      [{ witness: [] }, "parameter 'witness' must be a JSON object"],
      [{ updateKeys: 'z6Mk' }, "parameter 'updateKeys' must be an array of strings"],
      [{ nextKeyHashes: {} }, "parameter 'nextKeyHashes' must be an array of strings"],
      [{ method: 1 }, "parameter 'method' must be a string"],
      [{ scid: 1 }, "parameter 'scid' must be a string"],
    ];
    for (const [parameters, message] of cases) {
      const log = await appendRawLogEntry({ log: genesis, signer, parameters, versionTime: '2026-01-01T00:00:01Z' });
      await expect(resolveDIDFromLog(log, { verifier, witnessProofs: [] }), JSON.stringify(parameters)).rejects.toThrow(
        `version '2' ${message}`
      );
    }
  });

  test('a ttl outside the integers 0 to 2^31 - 1 is rejected', async () => {
    const { signer, verifier, log: genesis } = await setup();
    for (const ttl of ['3600', 'abc', -5, 1.5, true, {}, 2 ** 31]) {
      const log = await appendRawLogEntry({
        log: genesis,
        signer,
        parameters: { ttl },
        versionTime: '2026-01-01T00:00:01Z',
      });
      await expect(resolveDIDFromLog(log, { verifier, witnessProofs: [] }), JSON.stringify(ttl)).rejects.toThrow(
        "version '2' parameter 'ttl' must be an integer from 0 to 2147483647"
      );
    }
  });

  test('a ttl of 0 and a ttl of 2^31 - 1 are accepted', async () => {
    const { signer, verifier, log: genesis } = await setup();
    for (const ttl of [0, 2 ** 31 - 1]) {
      const log = await appendRawLogEntry({
        log: genesis,
        signer,
        parameters: { ttl },
        versionTime: '2026-01-01T00:00:01Z',
      });
      const resolved = await resolveDIDFromLog(log, { verifier, witnessProofs: [] });
      expect(resolved.meta.ttl, String(ttl)).toBe(ttl);
    }
  });
});
