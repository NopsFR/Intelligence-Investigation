import { assertSafeDestination, SsrfBlockedError } from "./ssrf";

const MAX_REDIRECTS = 5;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB

export interface SafeFetchOptions extends RequestInit {
  timeoutMs?: number;
  /** Set true for provider APIs with fixed, trusted hosts (skips SSRF check). */
  trustedHost?: boolean;
}

export class TimeoutError extends Error {
  constructor() {
    super("Request timed out");
    this.name = "TimeoutError";
  }
}

export class ResponseTooLargeError extends Error {
  constructor() {
    super("Response exceeded maximum allowed size");
    this.name = "ResponseTooLargeError";
  }
}

/**
 * A fetch wrapper enforcing: request timeout, bounded redirects with
 * per-hop SSRF revalidation, and a bounded response size. Used for every
 * outbound request the application makes — provider APIs and, critically,
 * user-supplied URLs inspected by the toolbox.
 */
export async function safeFetch(
  inputUrl: string,
  options: SafeFetchOptions = {}
): Promise<Response> {
  const { timeoutMs = 8000, trustedHost = false, ...init } = options;

  let currentUrl = inputUrl;
  if (!trustedHost) {
    await assertSafeDestination(currentUrl);
  }

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await fetch(currentUrl, {
        ...init,
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      if (controller.signal.aborted) throw new TimeoutError();
      throw err;
    } finally {
      clearTimeout(timer);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) return response;
      const nextUrl = new URL(location, currentUrl).toString();
      if (!trustedHost) {
        await assertSafeDestination(nextUrl);
      }
      currentUrl = nextUrl;
      continue;
    }

    return await enforceSizeLimit(response);
  }

  throw new Error("Too many redirects");
}

async function enforceSizeLimit(response: Response): Promise<Response> {
  const contentLength = response.headers.get("content-length");
  if (contentLength && Number(contentLength) > MAX_RESPONSE_BYTES) {
    throw new ResponseTooLargeError();
  }
  if (!response.body) return response;

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      throw new ResponseTooLargeError();
    }
    chunks.push(value);
  }
  const body = new Blob(chunks as BlobPart[]);
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

export { SsrfBlockedError };
