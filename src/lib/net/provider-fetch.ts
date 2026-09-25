import "server-only";
import type { z } from "zod";
import { assertHostnameAllowed } from "./policy";

export type ProviderErrorKind =
  | "timeout"
  | "network"
  | "http"
  | "invalid-json"
  | "schema"
  | "too-large"
  | "policy"
  | "aborted";

export class ProviderRequestError extends Error {
  constructor(
    message: string,
    public readonly kind: ProviderErrorKind,
    public readonly status?: number,
    public readonly retryAfterSeconds?: number
  ) {
    super(message);
    this.name = "ProviderRequestError";
  }
}

export interface ProviderRequestOptions {
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
  maxBytes?: number;
  /** Retries for idempotent requests on network errors / 5xx (not 429). */
  retries?: number;
  /** Status codes that are a valid answer rather than an error (e.g. 404 = not found). */
  acceptStatus?: number[];
}

export interface ProviderResponse {
  status: number;
  headers: Headers;
  body: Uint8Array;
  text: string;
  bytes: number;
  url: string;
  requests: number;
}

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
const USER_AGENT = "NOPS-Cyber-Intelligence/1.0 (+https://github.com/NopsFR/Intelligence-Investigation)";

async function readBounded(response: Response, maxBytes: number): Promise<{ body: Uint8Array; bytes: number }> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    throw new ProviderRequestError(`Response of ${declared} bytes exceeds the ${maxBytes} byte limit`, "too-large");
  }
  if (!response.body) return { body: new Uint8Array(0), bytes: 0 };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ProviderRequestError(`Response exceeded the ${maxBytes} byte limit`, "too-large");
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return { body: merged, bytes: total };
}

function retryAfter(headers: Headers): number | undefined {
  const value = headers.get("retry-after");
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return seconds;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, Math.round((date - Date.now()) / 1000)) : undefined;
}

async function attempt(url: string, options: ProviderRequestOptions, signal: AbortSignal): Promise<ProviderResponse> {
  let current = url;
  let requests = 0;
  for (let hop = 0; hop <= 3; hop++) {
    requests++;
    let response: Response;
    try {
      response = await fetch(current, {
        method: options.method ?? "GET",
        headers: { "user-agent": USER_AGENT, accept: "application/json", ...options.headers },
        body: options.body,
        redirect: "manual",
        signal,
        cache: "no-store",
      });
    } catch (err) {
      if (signal.aborted) {
        const reason = signal.reason;
        if (reason instanceof ProviderRequestError) throw reason;
        throw new ProviderRequestError("The provider did not respond within the configured timeout", "timeout");
      }
      const cause = (err as { cause?: { code?: string } }).cause;
      throw new ProviderRequestError(cause?.code ? `${cause.code}: ${(err as Error).message}` : (err as Error).message, "network");
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel().catch(() => undefined);
      if (!location) throw new ProviderRequestError("Redirect without a Location header", "http", response.status);
      const next = new URL(location, current);
      if (next.protocol !== "https:") throw new ProviderRequestError(`Refused redirect to non-HTTPS ${next.origin}`, "policy");
      try {
        assertHostnameAllowed(next.hostname);
      } catch (err) {
        throw new ProviderRequestError(`Refused redirect: ${(err as Error).message}`, "policy");
      }
      current = next.toString();
      continue;
    }

    const accepted = response.ok || options.acceptStatus?.includes(response.status);
    if (!accepted) {
      await response.body?.cancel().catch(() => undefined);
      throw new ProviderRequestError(`Provider returned HTTP ${response.status}`, "http", response.status, retryAfter(response.headers));
    }

    const { body, bytes } = await readBounded(response, options.maxBytes ?? DEFAULT_MAX_BYTES);
    return {
      status: response.status,
      headers: response.headers,
      body,
      get text() {
        return new TextDecoder().decode(body);
      },
      bytes,
      url: current,
      requests,
    };
  }
  throw new ProviderRequestError("Too many redirects", "http");
}

/** Performs an outbound request to a provider API with timeout, bounds and retry. */
export async function providerRequest(url: string, options: ProviderRequestOptions = {}): Promise<ProviderResponse> {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const signal = options.signal ? AbortSignal.any([options.signal, timeoutSignal]) : timeoutSignal;
  const retries = options.retries ?? ((options.method ?? "GET") === "GET" ? 1 : 0);

  let lastError: unknown;
  for (let i = 0; i <= retries; i++) {
    try {
      return await attempt(url, options, signal);
    } catch (err) {
      lastError = err;
      const transient =
        err instanceof ProviderRequestError &&
        (err.kind === "network" || (err.kind === "http" && (err.status ?? 0) >= 500));
      if (!transient || i === retries || signal.aborted) throw err;
      await new Promise((r) => setTimeout(r, 300 * 2 ** i));
    }
  }
  throw lastError;
}

/** Parses and validates a JSON body, raising classified provider errors. */
export function parseProviderJson<T>(text: string, schema: z.ZodType<T>, status?: number): T {
  let parsed: unknown;
  try {
    parsed = text.length ? JSON.parse(text) : null;
  } catch {
    throw new ProviderRequestError("The provider returned a response that is not valid JSON", "invalid-json", status);
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    const issue = result.error.issues[0];
    throw new ProviderRequestError(
      `Response did not match the expected schema (${issue?.path.join(".") || "root"}: ${issue?.message ?? "invalid"})`,
      "schema",
      status
    );
  }
  return result.data;
}

/** Fetches JSON and validates it against a schema. */
export async function providerJson<T>(url: string, schema: z.ZodType<T>, options: ProviderRequestOptions = {}): Promise<{ data: T; response: ProviderResponse }> {
  const response = await providerRequest(url, options);
  return { data: parseProviderJson(response.text, schema, response.status), response };
}
