import { DIDResolutionError, isDIDResolutionError } from '@interop/data-integrity-core';
import type { FetchLike } from '../interfaces.js';

type FetchResponse = Awaited<ReturnType<FetchLike>>;

const internalError = (message: string, cause?: unknown): DIDResolutionError =>
  new DIDResolutionError(message, { code: 'internalError', cause });

/**
 * Wraps a thrown value as a retrieval failure. A `DIDResolutionError` is
 * returned unchanged; anything else becomes one with code `internalError`,
 * the original as `cause`, and `prefix` before its message.
 */
export const toRetrievalError = (error: unknown, prefix = ''): DIDResolutionError => {
  if (isDIDResolutionError(error)) {
    return error;
  }
  const message = error instanceof Error ? error.message : String(error);
  return internalError(`${prefix}${message}`, error);
};

/**
 * Default deadline for one request and its body read. A resolution makes at
 * most two (`did.jsonl` and `did-witness.json`), which fits within the
 * specification's suggested 30 second limit on a whole resolution.
 */
const FETCH_TIMEOUT_MS = 10_000;

/** Default limit on the size of a response body, the specification's suggested 5 MiB. */
export const FETCH_MAX_BYTES = 5 * 1024 * 1024;

/**
 * Reads the declared `content-length`. Only a WHATWG `Headers` object (one
 * with a `get` method) is consulted; an adapter with plain-object headers
 * gets no early check, and its body is measured as it is read.
 */
const declaredContentLength = (response: FetchResponse): number =>
  Number(response.headers?.get?.('content-length') ?? Number.NaN);

/**
 * Returns a reader for a WHATWG `ReadableStream` body, or `undefined` when the
 * body is absent or is some other kind of stream (a Node `Readable` from
 * node-fetch, for example).
 */
const streamReader = (response: FetchResponse): ReadableStreamDefaultReader<Uint8Array> | undefined =>
  response.body?.getReader?.();

/** Cancels a WHATWG stream body, when the response has one, ignoring failures. */
const cancelBody = async (response: FetchResponse): Promise<void> => {
  await response.body?.cancel?.().catch(() => {});
};

/**
 * Whether the response reports that the request was redirected. A custom
 * fetch may ignore `redirect: 'error'`, so this is checked after the response
 * arrives. `response.url` is compared only when it is a non-empty, parseable
 * URL, since a synthesized response carries an empty one.
 */
const wasRedirected = (response: FetchResponse, url: string): boolean => {
  if (response.redirected === true) {
    return true;
  }
  if (typeof response.url !== 'string' || response.url === '') {
    return false;
  }
  try {
    return new URL(response.url).href !== new URL(url).href;
  } catch {
    return false;
  }
};

/**
 * Reads a response body as text, stopping once it passes `maxBytes`. A
 * declared `content-length` over the limit is rejected before any read. A
 * streamed body is cancelled at the limit, and when `signal` aborts. A
 * response with no WHATWG stream (an adapter object, a Node stream, React
 * Native) is read with `text()` and measured afterwards.
 */
const readBoundedText = async (
  response: FetchResponse,
  url: string,
  maxBytes: number,
  signal: AbortSignal
): Promise<string> => {
  const tooLarge = () => internalError(`Response body at ${url} exceeds the ${maxBytes} byte limit`);

  if (declaredContentLength(response) > maxBytes) {
    throw tooLarge();
  }

  const reader = streamReader(response);
  if (!reader) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw tooLarge();
    }
    return text;
  }

  // On the deadline, cancel the reader so a pending read() settles and the
  // loop below stops.
  const onAbort = () => {
    reader.cancel(signal.reason).catch(() => {});
  };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    if (signal.aborted) {
      onAbort();
    }
    const decoder = new TextDecoder();
    let received = 0;
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (signal.aborted) {
        throw signal.reason;
      }
      if (done) {
        return text + decoder.decode();
      }
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel().catch(() => {});
        throw tooLarge();
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
};

/**
 * Makes one GET request with a deadline, a body size limit, and redirects
 * refused. The deadline covers the request and the body read. It is passed to
 * `fetchFn` as an abort signal and also enforced here, so it holds when a
 * custom `fetchFn` ignores the signal. A response reporting a redirect is
 * refused too, for a custom `fetchFn` that ignores `redirect: 'error'`. The
 * body is read only for an `ok` response.
 *
 * A 404 returns `undefined`, so the caller decides what a missing file means.
 * Every other failure is thrown as a `DIDResolutionError` with code
 * `internalError`: any other non-`ok` status, the deadline, an oversized
 * body, a redirect, and any error thrown by `fetchFn` or while reading the
 * body (kept as `cause`).
 *
 * @param url {string} The URL to request.
 * @param fetchFn {FetchLike} The fetch implementation to call.
 * @param [options.timeoutMs] {number} Deadline in milliseconds for the request
 *   and body read. Defaults to 10 seconds.
 * @param [options.maxBytes] {number} Largest body, in bytes, that is returned.
 *   Defaults to 5 MiB.
 * @returns {Promise<string | undefined>} The body text, or `undefined` for a
 *   404.
 */
export async function fetchBounded(
  url: string,
  fetchFn: FetchLike,
  { timeoutMs = FETCH_TIMEOUT_MS, maxBytes = FETCH_MAX_BYTES }: { timeoutMs?: number; maxBytes?: number } = {}
): Promise<string | undefined> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = internalError(`Request to ${url} timed out after ${timeoutMs} ms`);
      reject(error);
      controller.abort(error);
    }, timeoutMs);
  });

  const request = async () => {
    try {
      const response = await fetchFn(url, { redirect: 'error', signal: controller.signal });
      if (wasRedirected(response, url)) {
        await cancelBody(response);
        throw internalError(`Request to ${url} was redirected; redirects are refused`);
      }
      if (!response.ok) {
        await cancelBody(response);
        if (response.status === 404) {
          return undefined;
        }
        throw internalError(`HTTP error! status: ${response.status}`);
      }
      return await readBoundedText(response, url, maxBytes, controller.signal);
    } catch (error) {
      throw toRetrievalError(error, `Request to ${url} failed: `);
    }
  };

  try {
    const pending = request();
    // The deadline may win the race; the abandoned request then rejects on abort.
    pending.catch(() => {});
    return await Promise.race([pending, deadline]);
  } finally {
    clearTimeout(timer);
  }
}
