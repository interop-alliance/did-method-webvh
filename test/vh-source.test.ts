import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type { IDIDResolutionResult } from '@interop/data-integrity-core';
import { afterAll, afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import { logToJsonlString } from '../src/utils.js';
import { dereference, deriveSrcReferences, resolveDID } from '../src/vh.js';
import { parseSourceReference } from '../src/vh-source.js';
import { stubGlobalFetchUnused } from './utils.js';
import { appendService, createUrlFetch, createVhFixture, createWitnessedVh } from './vh-helpers.js';

const rmeta = (result: IDIDResolutionResult) => result.didResolutionMetadata as { error?: string; message?: string };
const dmeta = (result: IDIDResolutionResult) => result.didDocumentMetadata as { versionId?: string };

const LOG_URL = 'https://example.com/users/alice/did.jsonl';
const WITNESS_URL = 'https://example.com/users/alice/did-witness.json';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('srcLog and srcWitness', () => {
  test('srcLog is fetched from exactly the URL given, with nothing appended', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log) });
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier, fetch });
    expect(rmeta(result).error).toBeUndefined();
    expect(result.didDocument?.id).toBe(f.did);
    expect(seen).toEqual([LOG_URL]);
  });

  test('a srcLog with a query keeps it, and any file name is accepted', async () => {
    const f = await createVhFixture();
    const url = 'https://example.com/logs/mine.jsonl?v=2';
    const { fetch, seen } = createUrlFetch({ [url]: logToJsonlString(f.log) });
    const result = await resolveDID(f.did, { srcLog: url, verifier: f.verifier, fetch });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([url]);
  });

  test('a 404 on srcLog is notFound', async () => {
    const f = await createVhFixture();
    const { fetch } = createUrlFetch({});
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier, fetch });
    expect(rmeta(result).error).toBe('notFound');
    expect(result.didDocument).toBeNull();
  });

  test('an empty srcLog body is notFound', async () => {
    const f = await createVhFixture();
    const { fetch } = createUrlFetch({ [LOG_URL]: '  \n' });
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier, fetch });
    expect(rmeta(result).error).toBe('notFound');
  });

  test('a srcLog body that is not JSON Lines is invalidDid', async () => {
    const f = await createVhFixture();
    const { fetch } = createUrlFetch({ [LOG_URL]: 'not json' });
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier, fetch });
    expect(rmeta(result).error).toBe('invalidDid');
  });

  test('a fetch failure other than a 404 is internalError', async () => {
    const f = await createVhFixture();
    const fetch = vi.fn(async () => new Response('', { status: 500 }));
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier, fetch });
    expect(rmeta(result).error).toBe('internalError');
  });

  test('srcWitness is not fetched when the log requires no witnesses', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log), [WITNESS_URL]: '[]' });
    const result = await resolveDID(f.did, {
      srcLog: LOG_URL,
      srcWitness: WITNESS_URL,
      verifier: f.verifier,
      fetch,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([LOG_URL]);
  });

  test('srcWitness is fetched, exactly as given, when the log requires witnesses', async () => {
    const w = await createWitnessedVh(1);
    const { fetch, seen } = createUrlFetch({
      [LOG_URL]: logToJsonlString(w.log),
      [WITNESS_URL]: JSON.stringify(w.didWitness),
    });
    const result = await resolveDID(w.did, {
      srcLog: LOG_URL,
      srcWitness: WITNESS_URL,
      verifier: w.verifier,
      fetch,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([LOG_URL, WITNESS_URL]);
  });

  test('a missing witness file is read as holding no proofs, so the threshold is unmet', async () => {
    const w = await createWitnessedVh(1);
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(w.log) });
    const result = await resolveDID(w.did, { srcLog: LOG_URL, srcWitness: WITNESS_URL, verifier: w.verifier, fetch });
    expect(rmeta(result).error).toBe('invalidDid');
    expect(seen).toEqual([LOG_URL, WITNESS_URL]);
  });

  test('a witness file that is not a JSON array is an error', async () => {
    const w = await createWitnessedVh(1);
    const { fetch } = createUrlFetch({ [LOG_URL]: logToJsonlString(w.log), [WITNESS_URL]: '{}' });
    const result = await resolveDID(w.did, { srcLog: LOG_URL, srcWitness: WITNESS_URL, verifier: w.verifier, fetch });
    expect(rmeta(result).error).toBe('invalidDid');
    expect(result.didDocument).toBeNull();
  });

  test('didWitness is used and srcWitness is not fetched', async () => {
    const w = await createWitnessedVh(1);
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(w.log) });
    const result = await resolveDID(w.did, { srcLog: LOG_URL, didWitness: w.didWitness, verifier: w.verifier, fetch });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([LOG_URL]);
  });

  test('the global fetch is used when no fetch override is given', async () => {
    const f = await createVhFixture();
    const globalFetch = stubGlobalFetchUnused();
    globalFetch.mockImplementation(async () => new Response(logToJsonlString(f.log)));
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier });
    expect(rmeta(result).error).toBeUndefined();
    expect(globalFetch.mock.calls[0][0]).toBe(LOG_URL);
  });
});

describe("network: 'none' and 'log-only'", () => {
  test("network 'none' fetches nothing and srcLog is notFound", async () => {
    const f = await createVhFixture();
    const globalFetch = stubGlobalFetchUnused();
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log) });
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier, fetch, network: 'none' });
    expect(rmeta(result).error).toBe('notFound');
    expect(seen).toEqual([]);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test("network 'none' still resolves a didLog without fetching", async () => {
    const f = await createVhFixture();
    const globalFetch = stubGlobalFetchUnused();
    const result = await resolveDID(f.did, { didLog: f.log, verifier: f.verifier, network: 'none' });
    expect(rmeta(result).error).toBeUndefined();
    expect(globalFetch).not.toHaveBeenCalled();
  });

  test("network 'log-only' fetches the log, and a required srcWitness is an error never requested", async () => {
    const w = await createWitnessedVh(1);
    const { fetch, seen } = createUrlFetch({
      [LOG_URL]: logToJsonlString(w.log),
      [WITNESS_URL]: JSON.stringify(w.didWitness),
    });
    const result = await resolveDID(w.did, {
      srcLog: LOG_URL,
      srcWitness: WITNESS_URL,
      verifier: w.verifier,
      fetch,
      network: 'log-only',
    });
    expect(rmeta(result).error).toBe('notFound');
    expect(result.didDocument).toBeNull();
    expect(seen).toEqual([LOG_URL]);
  });

  test("network 'log-only' resolves a witnessed log whose didWitness is supplied", async () => {
    const w = await createWitnessedVh(1);
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(w.log) });
    const result = await resolveDID(w.did, {
      srcLog: LOG_URL,
      didWitness: w.didWitness,
      verifier: w.verifier,
      fetch,
      network: 'log-only',
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([LOG_URL]);
  });

  test("network 'log-only' resolves an unwitnessed log", async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log) });
    const result = await resolveDID(f.did, { srcLog: LOG_URL, verifier: f.verifier, fetch, network: 'log-only' });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([LOG_URL]);
  });
});

describe('source reference validation', () => {
  const invalidReferences = [
    'https://192.168.1.1/x',
    'https://[2001:db8::1]/x',
    'https://example.com/did.jsonl#frag',
    'https://example.com/a/../did.jsonl',
    'https://example.com/a/%2e%2e/did.jsonl',
    'https://example.com',
    'https://',
    'did.jsonl',
    '/did.jsonl',
    '//example.com/did.jsonl',
    'http://example.com/x',
    'http://192.168.1.1/x',
  ];

  test('malformed references are invalidOptions and nothing is fetched', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({});
    for (const reference of invalidReferences) {
      const log = await resolveDID(f.did, { srcLog: reference, verifier: f.verifier, fetch });
      expect(rmeta(log).error, `srcLog ${reference}`).toBe('invalidOptions');
      const witness = await resolveDID(f.did, { didLog: f.log, srcWitness: reference, verifier: f.verifier, fetch });
      expect(rmeta(witness).error, `srcWitness ${reference}`).toBe('invalidOptions');
    }
    expect(seen).toEqual([]);
  });

  test('http://example.com/x is invalidOptions even for a local resolver', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({});
    const result = await resolveDID(f.did, {
      srcLog: 'http://example.com/x',
      verifier: f.verifier,
      fetch,
      local: true,
    });
    expect(rmeta(result).error).toBe('invalidOptions');
    expect(seen).toEqual([]);
  });

  test('a non-string srcLog is invalidOptions', async () => {
    const f = await createVhFixture();
    const result = await resolveDID(f.did, { srcLog: 5 as never, verifier: f.verifier });
    expect(rmeta(result).error).toBe('invalidOptions');
  });

  test('a reference that URL parsing would rewrite is invalidOptions', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({});
    const references = [
      'https://example.com/a/.\t./b/did.jsonl',
      'https://example.com\\..\\x/did.jsonl',
      'https://example.com/a\\b/did.jsonl',
      'https://example.com/a/did.jsonl\n',
      ' https://example.com/a/did.jsonl',
      'https://user:pw@example.com/did.jsonl',
      'https://user@example.com/did.jsonl',
    ];
    for (const srcLog of references) {
      const result = await resolveDID(f.did, { srcLog, verifier: f.verifier, fetch });
      expect(rmeta(result).error, JSON.stringify(srcLog)).toBe('invalidOptions');
    }
    expect(() => parseSourceReference('file:///tmp/a/.\t./did.jsonl', 'srcLog', true)).toThrow(/control character/);
    expect(seen).toEqual([]);
  });

  test('an unsupported-scheme srcWitness is an error only when the witness file is needed', async () => {
    const srcWitness = 'ipfs://bafy/did-witness.json';
    const f = await createVhFixture();
    const plain = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log) });
    const unneeded = await resolveDID(f.did, { srcLog: LOG_URL, srcWitness, verifier: f.verifier, fetch: plain.fetch });
    expect(rmeta(unneeded).error).toBeUndefined();
    expect(plain.seen).toEqual([LOG_URL]);

    const w = await createWitnessedVh(1);
    const witnessed = createUrlFetch({ [LOG_URL]: logToJsonlString(w.log) });
    const needed = await resolveDID(w.did, {
      srcLog: LOG_URL,
      srcWitness,
      verifier: w.verifier,
      fetch: witnessed.fetch,
    });
    expect(rmeta(needed).error).toBe('featureNotSupported');
    expect(witnessed.seen).toEqual([LOG_URL]);

    const withFragment = await resolveDID(f.did, {
      srcLog: LOG_URL,
      srcWitness: `${srcWitness}#x`,
      verifier: f.verifier,
      fetch: plain.fetch,
    });
    expect(rmeta(withFragment).error).toBe('invalidOptions');
  });

  test('a scheme the library does not retrieve is featureNotSupported', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({});
    for (const local of [false, true]) {
      const result = await resolveDID(f.did, { srcLog: 'ipfs://x/y', verifier: f.verifier, fetch, local });
      expect(rmeta(result).error).toBe('featureNotSupported');
    }
    expect(seen).toEqual([]);
  });

  test('a validated https reference is returned as a normalized URL', () => {
    expect(parseSourceReference('https://example.com/a/b.jsonl', 'srcLog', false)).toEqual({
      kind: 'web',
      url: 'https://example.com/a/b.jsonl',
    });
  });
});

describe('local resolver references', () => {
  const loopback = ['http://localhost:8080/x.jsonl', 'http://127.0.0.1/x', 'http://127.0.0.1:3000/x', 'http://[::1]/x'];

  test('a loopback http reference is invalidOptions without local', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({});
    for (const url of loopback) {
      const result = await resolveDID(f.did, { srcLog: url, verifier: f.verifier, fetch });
      expect(rmeta(result).error, url).toBe('invalidOptions');
      expect(rmeta(result).message, url).toMatch(/local/);
    }
    expect(seen).toEqual([]);
  });

  test('a loopback http reference works with local', async () => {
    const f = await createVhFixture();
    for (const url of loopback) {
      const { fetch, seen } = createUrlFetch({ [new URL(url).href]: logToJsonlString(f.log) });
      const result = await resolveDID(f.did, { srcLog: url, verifier: f.verifier, fetch, local: true });
      expect(rmeta(result).error, url).toBeUndefined();
      expect(seen, url).toEqual([new URL(url).href]);
    }
  });

  describe('file: references', () => {
    let dir: string;
    beforeAll(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'did-vh-test-'));
    });
    afterAll(() => {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    test('are invalidOptions without local', async () => {
      const f = await createVhFixture();
      const file = path.join(dir, 'did.jsonl');
      fs.writeFileSync(file, logToJsonlString(f.log));
      const result = await resolveDID(f.did, { srcLog: pathToFileURL(file).href, verifier: f.verifier });
      expect(rmeta(result).error).toBe('invalidOptions');
      expect(rmeta(result).message).toMatch(/local/);
    });

    test('are read with local, without any network request', async () => {
      const f = await createVhFixture();
      const globalFetch = stubGlobalFetchUnused();
      const file = path.join(dir, 'did.jsonl');
      fs.writeFileSync(file, logToJsonlString(f.log));
      const result = await resolveDID(f.did, {
        srcLog: pathToFileURL(file).href,
        verifier: f.verifier,
        local: true,
      });
      expect(rmeta(result).error).toBeUndefined();
      expect(result.didDocument?.id).toBe(f.did);
      expect(globalFetch).not.toHaveBeenCalled();
    });

    test("are still read with network: 'none', since a local file is not a network request", async () => {
      const f = await createVhFixture();
      const file = path.join(dir, 'none.jsonl');
      fs.writeFileSync(file, logToJsonlString(f.log));
      const result = await resolveDID(f.did, {
        srcLog: pathToFileURL(file).href,
        verifier: f.verifier,
        local: true,
        network: 'none',
      });
      expect(rmeta(result).error).toBeUndefined();
    });

    test('a witnessed log reads srcWitness from a file too', async () => {
      const w = await createWitnessedVh(1);
      const logFile = path.join(dir, 'w.jsonl');
      const witnessFile = path.join(dir, 'w-witness.json');
      fs.writeFileSync(logFile, logToJsonlString(w.log));
      fs.writeFileSync(witnessFile, JSON.stringify(w.didWitness));
      const result = await resolveDID(w.did, {
        srcLog: pathToFileURL(logFile).href,
        srcWitness: pathToFileURL(witnessFile).href,
        verifier: w.verifier,
        local: true,
        network: 'log-only',
      });
      expect(rmeta(result).error).toBeUndefined();
    });

    test('a missing file is notFound', async () => {
      const f = await createVhFixture();
      const result = await resolveDID(f.did, {
        srcLog: pathToFileURL(path.join(dir, 'missing.jsonl')).href,
        verifier: f.verifier,
        local: true,
      });
      expect(rmeta(result).error).toBe('notFound');
    });

    test('a file URL with a query, a fragment or a remote host is invalidOptions', async () => {
      const f = await createVhFixture();
      for (const url of [
        'file:///tmp/x.jsonl?a=1',
        'file:///tmp/x.jsonl#f',
        'file://example.com/tmp/x.jsonl',
        'file:x',
      ]) {
        const result = await resolveDID(f.did, { srcLog: url, verifier: f.verifier, local: true });
        expect(rmeta(result).error, url).toBe('invalidOptions');
      }
    });
  });
});

describe('dereference and src', () => {
  const src = (value: string) => `src=${encodeURIComponent(value)}`;

  test('src derives srcLog by appending /did.jsonl, and fetches the witness file only for a witnessed log', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log) });
    const result = await dereference(`${f.did}?${src('https://example.com/users/alice/')}`, {
      verifier: f.verifier,
      fetch,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(result.didDocument?.id).toBe(f.did);
    expect(seen).toEqual([LOG_URL]);

    const w = await createWitnessedVh(1);
    const witnessed = createUrlFetch({
      [LOG_URL]: logToJsonlString(w.log),
      [WITNESS_URL]: JSON.stringify(w.didWitness),
    });
    const wResult = await dereference(`${w.did}?${src('https://example.com/users/alice/')}`, {
      verifier: w.verifier,
      fetch: witnessed.fetch,
    });
    expect(rmeta(wResult).error).toBeUndefined();
    expect(witnessed.seen).toEqual([LOG_URL, WITNESS_URL]);
  });

  test('a src without a trailing slash derives the same references', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log) });
    await dereference(`${f.did}?${src('https://example.com/users/alice')}`, { verifier: f.verifier, fetch });
    expect(seen).toEqual([LOG_URL]);
  });

  test('a src with no path derives https://example.com/did.jsonl', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ 'https://example.com/did.jsonl': logToJsonlString(f.log) });
    const result = await dereference(`${f.did}?${src('https://example.com')}`, { verifier: f.verifier, fetch });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual(['https://example.com/did.jsonl']);
  });

  test('a version parameter in the URL selects the version', async () => {
    const f = await createVhFixture();
    const log = await appendService(f, f.log, 'one');
    const url = (query: string) => `${f.did}?${query}`;

    const byNumber = await dereference(url('versionNumber=1'), { didLog: log, verifier: f.verifier });
    expect(dmeta(byNumber).versionId).toBe(log[0].versionId);

    const byId = await dereference(url(`versionId=${log[0].versionId}`), { didLog: log, verifier: f.verifier });
    expect(dmeta(byId).versionId).toBe(log[0].versionId);

    const byTime = await dereference(url(`versionTime=${log[1].versionTime}`), { didLog: log, verifier: f.verifier });
    expect(dmeta(byTime).versionId).toBe(log[1].versionId);

    // The URL replaces a selector in the options.
    const replaced = await dereference(url('versionNumber=1'), { didLog: log, verifier: f.verifier, versionNumber: 2 });
    expect(dmeta(replaced).versionId).toBe(log[0].versionId);
  });

  test('a version parameter combines with src', async () => {
    const f = await createVhFixture();
    const { fetch } = createUrlFetch({ [LOG_URL]: logToJsonlString(f.log) });
    const result = await dereference(`${f.did}?versionNumber=1&${src('https://example.com/users/alice/')}`, {
      verifier: f.verifier,
      fetch,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(dmeta(result).versionId).toBe(f.log[0].versionId);
  });

  test('a bare DID with didLog resolves, and a fragment is not applied', async () => {
    const f = await createVhFixture();
    const result = await dereference(`${f.did}#key-1`, { didLog: f.log, verifier: f.verifier });
    expect(rmeta(result).error).toBeUndefined();
    expect(result.didDocument?.id).toBe(f.did);
  });

  test('a URL with a path is notFound', async () => {
    const f = await createVhFixture();
    for (const suffix of ['/foo', '/foo/bar?versionNumber=1']) {
      const result = await dereference(`${f.did}${suffix}`, { didLog: f.log, verifier: f.verifier });
      expect(rmeta(result).error, suffix).toBe('notFound');
      expect(result.didDocument).toBeNull();
    }
  });

  test('src is validated but not fetched when options.didLog is given', async () => {
    const f = await createVhFixture();
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: 'ignored' });
    const result = await dereference(`${f.did}?${src('https://example.com/users/alice/')}`, {
      didLog: f.log,
      verifier: f.verifier,
      fetch,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([]);

    const bad = await dereference(`${f.did}?${src('http://example.com/x')}`, {
      didLog: f.log,
      verifier: f.verifier,
      fetch,
    });
    expect(rmeta(bad).error).toBe('invalidDidUrl');
    expect(seen).toEqual([]);
  });

  test("an options.srcLog takes precedence over the URL's src, and derived srcWitness is not used", async () => {
    const f = await createVhFixture();
    const own = 'https://other.example/my.jsonl';
    const { fetch, seen } = createUrlFetch({ [own]: logToJsonlString(f.log) });
    const result = await dereference(`${f.did}?${src('https://example.com/users/alice/')}`, {
      srcLog: own,
      verifier: f.verifier,
      fetch,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([own]);
  });

  test('an options.didWitness suppresses the derived srcWitness', async () => {
    const w = await createWitnessedVh(1);
    const { fetch, seen } = createUrlFetch({ [LOG_URL]: logToJsonlString(w.log) });
    const result = await dereference(`${w.did}?${src('https://example.com/users/alice/')}`, {
      didWitness: w.didWitness,
      verifier: w.verifier,
      fetch,
    });
    expect(rmeta(result).error).toBeUndefined();
    expect(seen).toEqual([LOG_URL]);
  });

  test('without any log source, a plain DID URL is invalidOptions', async () => {
    const f = await createVhFixture();
    const result = await dereference(f.did, { verifier: f.verifier });
    expect(rmeta(result).error).toBe('invalidOptions');
  });

  describe('invalidDidUrl', () => {
    const cases: [string, (did: string) => string][] = [
      ['file: src', (did) => `${did}?${src('file:///tmp/x')}`],
      ['http: src', (did) => `${did}?${src('http://example.com/x')}`],
      ['http: loopback src', (did) => `${did}?${src('http://localhost/x')}`],
      ['query inside src', (did) => `${did}?${src('https://example.com/x?a=1')}`],
      ['fragment inside src', (did) => `${did}?${src('https://example.com/x#f')}`],
      ['two src params', (did) => `${did}?${src('https://example.com/a')}&${src('https://example.com/b')}`],
      ['IP host src', (did) => `${did}?${src('https://192.168.1.1/x')}`],
      ['IPv6 host src', (did) => `${did}?${src('https://[::1]/x')}`],
      ['.. segment', (did) => `${did}?${src('https://example.com/a/../b')}`],
      ['encoded .. segment', (did) => `${did}?src=https%3A%2F%2Fexample.com%2Fa%2F%252e%252e%2Fb`],
      ['empty middle segment', (did) => `${did}?${src('https://example.com/a//b')}`],
      ['relative src', (did) => `${did}?${src('users/alice')}`],
      ['non-hierarchical scheme', (did) => `${did}?${src('urn:example:x')}`],
      ['malformed percent-encoding', (did) => `${did}?src=%E0%A4%A`],
      ['unknown parameter', (did) => `${did}?foo=bar`],
      ['unknown parameter beside src', (did) => `${did}?${src('https://example.com/x')}&foo=bar`],
      ['didLog parameter', (did) => `${did}?didLog=abc`],
      ['didWitness parameter', (did) => `${did}?didWitness=abc`],
      ['srcLog parameter', (did) => `${did}?srcLog=${encodeURIComponent('https://example.com/did.jsonl')}`],
      ['srcWitness parameter', (did) => `${did}?srcWitness=${encodeURIComponent('https://example.com/w.json')}`],
      ['checkWatchers parameter', (did) => `${did}?checkWatchers=1`],
      ['extraWatchers parameter', (did) => `${did}?extraWatchers=x`],
      ['minCopies parameter', (did) => `${did}?minCopies=2`],
      ['includeDidLog parameter', (did) => `${did}?includeDidLog=true`],
    ];

    test.each(cases)('%s', async (_name, build) => {
      const f = await createVhFixture();
      const { fetch, seen } = createUrlFetch({});
      const result = await dereference(build(f.did), { verifier: f.verifier, fetch });
      expect(rmeta(result).error).toBe('invalidDidUrl');
      expect(result.didDocument).toBeNull();
      expect(seen).toEqual([]);
    });

    test('a DID that is not did:vh syntax is invalidDid', async () => {
      const f = await createVhFixture();
      const result = await dereference(`did:webvh:abc:example.com?${src('https://example.com/x')}`, {
        verifier: f.verifier,
      });
      expect(rmeta(result).error).toBe('invalidDid');
    });

    test('a non-string URL', async () => {
      const result = await dereference(5 as never);
      expect(rmeta(result).error).toBe('invalidDidUrl');
    });
  });
});

describe('deriveSrcReferences', () => {
  const codeOf = (fn: () => unknown) => {
    try {
      fn();
    } catch (error) {
      return (error as { code?: string }).code;
    }
    return undefined;
  };

  test('appends /did.jsonl and /did-witness.json', () => {
    expect(deriveSrcReferences('https://example.com/users/alice')).toEqual({
      srcLog: 'https://example.com/users/alice/did.jsonl',
      srcWitness: 'https://example.com/users/alice/did-witness.json',
    });
  });

  test('removes one trailing slash', () => {
    expect(deriveSrcReferences('https://example.com/users/alice/').srcLog).toBe(
      'https://example.com/users/alice/did.jsonl'
    );
    expect(deriveSrcReferences('https://example.com/').srcLog).toBe('https://example.com/did.jsonl');
  });

  test('an https value may have an empty path', () => {
    expect(deriveSrcReferences('https://example.com')).toEqual({
      srcLog: 'https://example.com/did.jsonl',
      srcWitness: 'https://example.com/did-witness.json',
    });
  });

  test('another hierarchical scheme is accepted', () => {
    expect(deriveSrcReferences('ipns://k51/x')).toEqual({
      srcLog: 'ipns://k51/x/did.jsonl',
      srcWitness: 'ipns://k51/x/did-witness.json',
    });
  });

  test('refuses with code invalidDidUrl', () => {
    const bad = [
      'file:///tmp/x',
      'FILE:///tmp/x',
      'http://example.com/x',
      'HTTP://localhost/x',
      'https://example.com/x?a=1',
      'https://example.com/x#f',
      'ipns://k51/x?a=1',
      'https://192.168.1.1/x',
      'https://[::1]/x',
      'https://example.com/a/../b',
      'https://example.com/a/./b',
      'https://example.com/a//b',
      'https://example.com/a//',
      'https://example.com/a/%2e%2e/b',
      'https://example.com/a/%2F/b',
      'https:///x',
      'https:example.com',
      'ipns:k51/x',
      'urn:example:x',
      'example.com/x',
      '/x',
      '',
    ];
    for (const value of bad) {
      expect(
        codeOf(() => deriveSrcReferences(value)),
        value
      ).toBe('invalidDidUrl');
    }
  });
});
