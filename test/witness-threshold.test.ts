import { describe, expect, test } from 'vitest';
import type { WitnessParameter } from '../src/interfaces.js';
import { resolveDIDFromLog, updateDID } from '../src/method.js';
import { toResolutionResult } from '../src/resolver-result.js';
import { validateWitnessParameter } from '../src/witness.js';
import { signWitnessProofEntry } from '../src/witness-signing.js';
import { appendRawLogEntry, createTestDID, createTestSigner, generateTestVerificationMethod } from './utils.js';

const invalidThresholds: unknown[] = ['1', '1abc', 1.5];

const setup = async () => {
  const witnessKey = await generateTestVerificationMethod();
  return { witnessKey, witnesses: [{ id: `did:key:${witnessKey.publicKeyMultibase}` }] };
};

describe('witness threshold validation', () => {
  test('validateWitnessParameter rejects string and fractional thresholds', async () => {
    const { witnesses } = await setup();
    for (const threshold of invalidThresholds) {
      expect(() => validateWitnessParameter({ witnesses, threshold: threshold as number }), String(threshold)).toThrow(
        'Witness threshold must be an integer'
      );
    }
  });

  test('the integer message carries the JSON form of the value', async () => {
    const { witnesses } = await setup();
    expect(() => validateWitnessParameter({ witnesses, threshold: '2' as unknown as number })).toThrow(
      'Witness threshold must be an integer: "2"'
    );
    expect(() => validateWitnessParameter({ witnesses, threshold: 1.5 })).toThrow(
      'Witness threshold must be an integer: 1.5'
    );
  });

  test('an integer threshold out of range is still rejected on its raw value', async () => {
    const { witnesses } = await setup();
    for (const threshold of [0, 2, -1]) {
      expect(() => validateWitnessParameter({ witnesses, threshold }), String(threshold)).toThrow(
        'Witness threshold must be between 1 and the number of witnesses'
      );
    }
  });

  test('createDID rejects string and fractional thresholds', async () => {
    const { witnesses } = await setup();
    for (const threshold of invalidThresholds) {
      await expect(
        createTestDID({ witness: { witnesses, threshold: threshold as number } }),
        String(threshold)
      ).rejects.toThrow('Witness threshold must be an integer');
    }
  });

  test('resolution rejects a log entry with a non-integer threshold, including a clean "2"', async () => {
    const { witnesses } = await setup();
    const { signer, verifier, log: genesis } = await createTestDID();

    for (const threshold of [...invalidThresholds, '2']) {
      const log = await appendRawLogEntry({ log: genesis, signer, parameters: { witness: { witnesses, threshold } } });
      await expect(resolveDIDFromLog(log, { verifier, witnessProofs: [] }), String(threshold)).rejects.toThrow(
        'Witness threshold must be an integer'
      );
    }
  });
});

describe('malformed and disabled witness parameters', () => {
  test('validateWitnessParameter rejects a non-integer threshold with an empty or absent witness list', () => {
    for (const threshold of invalidThresholds) {
      for (const witness of [{ threshold }, { witnesses: [], threshold }]) {
        expect(() => validateWitnessParameter(witness as WitnessParameter), JSON.stringify(witness)).toThrow(
          'Witness threshold must be an integer'
        );
      }
    }
  });

  test('validateWitnessParameter rejects a witness list that is not an array', () => {
    for (const witnesses of ['abc', {}]) {
      expect(() => validateWitnessParameter({ threshold: 1, witnesses } as unknown as WitnessParameter)).toThrow(
        'Witness list must be a non-empty array'
      );
    }
  });

  test('resolution rejects a log entry with a non-integer threshold and no witnesses', async () => {
    const { signer, verifier, log: genesis } = await createTestDID();

    for (const witness of [{ threshold: '2' }, { witnesses: [], threshold: 1.5 }]) {
      const log = await appendRawLogEntry({ log: genesis, signer, parameters: { witness } });
      await expect(resolveDIDFromLog(log, { verifier, witnessProofs: [] }), JSON.stringify(witness)).rejects.toThrow(
        'Witness threshold must be an integer'
      );
    }
  });

  test('only {} and null disable witnessing', () => {
    expect(() => validateWitnessParameter({})).not.toThrow();
    expect(() => validateWitnessParameter(null)).not.toThrow();
  });

  test('a witness parameter other than {} needs a non-empty witness list and a threshold', async () => {
    const { witnesses } = await setup();
    const cases: [unknown, string][] = [
      [{ threshold: 3, witnesses: [] }, 'Witness list must be a non-empty array'],
      [{ threshold: 0, witnesses: [] }, 'Witness list must be a non-empty array'],
      [{ threshold: 3 }, 'Witness list must be a non-empty array'],
      [{ foo: 1 }, 'Witness list must be a non-empty array'],
      [{ witnesses }, 'Witness threshold is required'],
    ];
    for (const [witness, message] of cases) {
      expect(() => validateWitnessParameter(witness as WitnessParameter), JSON.stringify(witness)).toThrow(message);
    }
  });

  test('resolution rejects a malformed witness parameter instead of treating it as no witnesses', async () => {
    const { witnesses } = await setup();
    const { signer, verifier, log: genesis } = await createTestDID();
    const cases: [unknown, string][] = [
      [{ threshold: 3, witnesses: [] }, 'Witness list must be a non-empty array'],
      [{ threshold: 3 }, 'Witness list must be a non-empty array'],
      [{ foo: 1 }, 'Witness list must be a non-empty array'],
      [{ witnesses }, 'Witness threshold is required'],
    ];
    for (const [witness, message] of cases) {
      const log = await appendRawLogEntry({ log: genesis, signer, parameters: { witness } });
      await expect(resolveDIDFromLog(log, { verifier, witnessProofs: [] }), JSON.stringify(witness)).rejects.toThrow(
        message
      );
    }
  });

  test('resolution rejects a witness list that is not an array with the validation message', async () => {
    const { signer, verifier, log: genesis } = await createTestDID();
    for (const witnesses of ['abc', {}]) {
      const log = await appendRawLogEntry({
        log: genesis,
        signer,
        parameters: { witness: { threshold: 1, witnesses } },
      });
      await expect(resolveDIDFromLog(log, { verifier, witnessProofs: [] }), JSON.stringify(witnesses)).rejects.toThrow(
        'Witness list must be a non-empty array'
      );
    }
  });

  test('a key other than threshold and witnesses does not invalidate a witness parameter', async () => {
    const { witnesses } = await setup();
    expect(() => validateWitnessParameter({ threshold: 1, witnesses, foo: 1 } as WitnessParameter)).not.toThrow();
  });

  test('createDID and updateDID write {} for witness input with no witnesses', async () => {
    const inputs = [null, { threshold: 0, witnesses: [] }, { threshold: 2, witnesses: [] }, { threshold: 2 }];
    for (const witness of inputs) {
      const { signer, verifier, log } = await createTestDID({ witness: witness as WitnessParameter });
      expect(log[0].parameters.witness, JSON.stringify(witness)).toEqual({});
      const updated = await updateDID({ log, signer, verifier, witnessProofs: [], witness });
      expect(updated.log[1].parameters.witness, JSON.stringify(witness)).toEqual({});
      expect((await resolveDIDFromLog(updated.log, { verifier, witnessProofs: [] })).meta.witness).toEqual({});
    }
  });

  test('createDID and updateDID reject a non-integer threshold with no witnesses', async () => {
    const { signer, verifier, log } = await createTestDID();
    for (const witness of [{ threshold: '2', witnesses: [] }, { threshold: 1.5 }]) {
      const input = witness as unknown as WitnessParameter;
      await expect(createTestDID({ witness: input }), JSON.stringify(witness)).rejects.toThrow(
        'Witness threshold must be an integer'
      );
      await expect(updateDID({ log, signer, verifier, witnessProofs: [], witness: input })).rejects.toThrow(
        'Witness threshold must be an integer'
      );
    }
  });
});

describe('witness threshold and ttl in resolution metadata', () => {
  test('the resolution result carries string threshold and ttl while log entries and writer meta keep numbers', async () => {
    const { witnessKey, witnesses } = await setup();
    const { signer, verifier, ...created } = await createTestDID({
      witness: { witnesses, threshold: 1 },
      created: '2026-01-01T00:00:00Z',
    });
    const witnessProofs = [
      await signWitnessProofEntry({
        trustedLog: [],
        candidateLog: created.log,
        witnessSigner: createTestSigner(witnessKey),
        witnessProofs: [],
        verifier,
      }),
    ];

    const resolved = await resolveDIDFromLog(created.log, { verifier, witnessProofs });
    const { didDocumentMetadata } = toResolutionResult(resolved);
    expect(didDocumentMetadata.witness).toEqual({ witnesses, threshold: '1' });
    expect(didDocumentMetadata.ttl).toBe('3600');
    expect(created.log[0].parameters.witness?.threshold).toBe(1);
    expect(created.meta.witness?.threshold).toBe(1);
    expect(resolved.meta.witness?.threshold).toBe(1);
    expect(created.meta.ttl).toBe(3600);
    expect(resolved.meta.ttl).toBe(3600);

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      witnessProofs,
      witness: { witnesses, threshold: 1 },
      updated: '2026-01-01T00:00:01Z',
    });
    expect(updated.log[1].parameters.witness?.threshold).toBe(1);
    expect(updated.meta.witness?.threshold).toBe(1);
  });

  test('a witness without a threshold stays without one in the result', () => {
    const { didDocumentMetadata } = toResolutionResult({
      did: 'did:webvh:x:example.com',
      doc: null,
      meta: { witness: {} },
    });
    expect(didDocumentMetadata.witness).toEqual({});
  });
});
