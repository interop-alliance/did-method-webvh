import { afterEach, describe, expect, test, vi } from 'vitest';
import { createNextVersionTime, parseUtcIso8601VersionTime } from '../src/utils/iso8601-datetime.js';
import { createDate } from '../src/utils.js';

describe('ISO8601 DateTime Validation', () => {
  test('Accepts Z timezone', () => {
    const result = parseUtcIso8601VersionTime('2025-11-02T10:20:30Z', 'test');
    expect(result).toBeInstanceOf(Date);
  });

  test('Rejects non-00:00 UTC offset', () => {
    expect(() => {
      parseUtcIso8601VersionTime('2025-11-02T10:20:30+01:00', 'test');
    }).toThrow('must be in UTC (Z or +00:00), found +01:00');
  });
});

describe('createNextVersionTime', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  test('bumps to previous + 1s when wall-clock now collides within the same second', () => {
    // versionTime is trimmed to whole seconds, so a `now` in the same second as
    // the previous entry must not produce an equal (colliding) timestamp.
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-25T12:00:00.400Z'));
    const next = createNextVersionTime('2026-06-25T12:00:00Z', undefined, createDate);
    expect(next).toBe('2026-06-25T12:00:01Z');
    expect(new Date(next).getTime()).toBeGreaterThan(new Date('2026-06-25T12:00:00Z').getTime());
  });

  test('uses the trimmed wall-clock now when it is already past previous', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-25T12:00:05.900Z'));
    const next = createNextVersionTime('2026-06-25T12:00:00Z', undefined, createDate);
    expect(next).toBe('2026-06-25T12:00:05Z');
  });

  test('rejects a requested time that trims down to the previous second', () => {
    expect(() => createNextVersionTime('2026-06-25T12:00:00Z', '2026-06-25T12:00:00.500Z', createDate)).toThrow(
      'must be greater than previous versionTime'
    );
  });

  test('accepts a requested time strictly greater than previous', () => {
    const next = createNextVersionTime('2026-06-25T12:00:00Z', '2026-06-25T12:00:01Z', createDate);
    expect(next).toBe('2026-06-25T12:00:01Z');
  });
});
