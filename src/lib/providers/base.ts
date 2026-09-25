import { z } from "zod";
import { ResponseTooLargeError, safeFetch, TimeoutError } from "@/lib/security/safeFetch";
import type { NormalizedResult, ProviderOutcome, ProviderStatus } from "@/types/provider";

export interface RequestJsonOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
  trustedHost?: boolean;
  method?: string;
  body?: BodyInit;
}

export class ProviderHttpError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ProviderHttpError";
  }
}

/**
 * Fetches JSON from a provider endpoint (always a fixed, trusted host —
 * these are our own hardcoded API base URLs, not user input) and classifies
 * failures into the small set of statuses the rest of the app understands.
 */
export async function requestJson<T>(
  url: string,
  schema: z.ZodType<T>,
  options: RequestJsonOptions = {}
): Promise<T> {
  const response = await safeFetch(url, {
    timeoutMs: options.timeoutMs ?? 8000,
    headers: options.headers,
    trustedHost: options.trustedHost ?? true,
    method: options.method,
    body: options.body,
  });

  if (response.status === 401 || response.status === 403) {
    throw new ProviderHttpError(response.status, "Authentication failed");
  }
  if (response.status === 429) {
    throw new ProviderHttpError(429, "Rate limited");
  }
  if (!response.ok) {
    throw new ProviderHttpError(response.status, `Upstream returned HTTP ${response.status}`);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new Error("INVALID_JSON");
  }

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    throw new Error("SCHEMA_MISMATCH");
  }
  return parsed.data;
}

export function classifyError(err: unknown): { status: ProviderStatus; errorType: string; errorMessage: string } {
  if (err instanceof TimeoutError) {
    return { status: "TIMEOUT", errorType: "timeout", errorMessage: "The provider did not respond within the configured timeout." };
  }
  if (err instanceof ResponseTooLargeError) {
    return { status: "INVALID_RESPONSE", errorType: "response_too_large", errorMessage: "The provider response exceeded the maximum allowed size." };
  }
  if (err instanceof ProviderHttpError) {
    if (err.status === 401 || err.status === 403) {
      return {
        status: "AUTH_FAILED",
        errorType: "auth_failed",
        errorMessage: "The provider rejected this request (401/403). If this provider requires an API key, verify it is configured correctly.",
      };
    }
    if (err.status === 429) {
      return { status: "RATE_LIMITED", errorType: "rate_limited", errorMessage: "This provider is temporarily unavailable for this investigation." };
    }
    if (err.status >= 500) {
      return { status: "UNAVAILABLE", errorType: "upstream_5xx", errorMessage: `Provider returned HTTP ${err.status}.` };
    }
    return { status: "INVALID_RESPONSE", errorType: "upstream_4xx", errorMessage: `Provider returned HTTP ${err.status}.` };
  }
  if (err instanceof Error) {
    if (err.message === "INVALID_JSON") {
      return { status: "INVALID_RESPONSE", errorType: "invalid_json", errorMessage: "The provider returned a response that could not be parsed." };
    }
    if (err.message === "SCHEMA_MISMATCH") {
      return { status: "INVALID_RESPONSE", errorType: "schema_mismatch", errorMessage: "The provider response did not match the expected schema." };
    }
    if (err.name === "SsrfBlockedError") {
      return { status: "INVALID_RESPONSE", errorType: "ssrf_blocked", errorMessage: "Destination blocked by network safety controls." };
    }
    if (err.name === "AbortError") {
      return { status: "TIMEOUT", errorType: "timeout", errorMessage: "The provider did not respond within the configured timeout." };
    }
    return { status: "NETWORK_ERROR", errorType: "network_error", errorMessage: err.message || "Network request failed." };
  }
  return { status: "NETWORK_ERROR", errorType: "unknown", errorMessage: "An unknown error occurred." };
}

export function successOutcome(provider: string, latencyMs: number, normalized: NormalizedResult, raw?: unknown): ProviderOutcome {
  const isEmpty = !normalized.fields || Object.keys(normalized.fields).length === 0;
  return {
    provider,
    status: isEmpty ? "EMPTY" : "SUCCESS",
    latencyMs,
    retrievedAt: new Date().toISOString(),
    normalized,
    raw,
  };
}

export function failureOutcome(provider: string, latencyMs: number, err: unknown): ProviderOutcome {
  const { status, errorType, errorMessage } = classifyError(err);
  return {
    provider,
    status,
    latencyMs,
    retrievedAt: new Date().toISOString(),
    errorType,
    errorMessage,
  };
}

export function notConfiguredOutcome(provider: string): ProviderOutcome {
  return {
    provider,
    status: "NOT_CONFIGURED",
    latencyMs: 0,
    retrievedAt: new Date().toISOString(),
    errorMessage: `Add the required API key to enable ${provider}.`,
  };
}

export async function timed<T>(fn: () => Promise<T>): Promise<{ result: T; latencyMs: number }> {
  const start = Date.now();
  const result = await fn();
  return { result, latencyMs: Date.now() - start };
}
