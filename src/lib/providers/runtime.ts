import "server-only";
import type { InvestigationMode, ObservableType, ProviderDiagnostics, ProviderOutcome, ProviderStatus } from "@/lib/core/types";
import { ProviderRequestError, parseProviderJson, providerJson, providerRequest } from "@/lib/net/provider-fetch";
import { TargetRequestError } from "@/lib/net/target";
import { NetworkPolicyError } from "@/lib/net/policy";
import type { ProviderDefinition, ProviderRunContext, ProviderRunResult } from "./types";

export class ProviderSkip extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProviderSkip";
  }
}

export interface CacheStore {
  get(provider: string, key: string): Promise<ProviderOutcome | null>;
  set(provider: string, key: string, outcome: ProviderOutcome, ttlSeconds: number): Promise<void>;
}

export interface QuotaStore {
  /** Returns true when the request fits in the budget (and records it). */
  consume(key: string, limit: number, windowSeconds: number): Promise<boolean>;
}

export interface RuntimeServices {
  cache?: CacheStore;
  quota?: QuotaStore;
  env?: Record<string, string | undefined>;
  logger?: (message: string, meta?: Record<string, unknown>) => void;
  catalog?: (id: string) => ProviderDefinition | undefined;
}

export interface ExecuteInput {
  observable: string;
  type: ObservableType;
  mode: InvestigationMode;
  signal?: AbortSignal;
  /** Bypass the cache (re-run / force refresh). */
  fresh?: boolean;
  dependencies?: Map<string, ProviderOutcome>;
}

export function readApiKey(def: ProviderDefinition, env: Record<string, string | undefined> = process.env): string | undefined {
  if (def.auth.type === "none") return undefined;
  for (const name of def.auth.env) {
    const value = env[name]?.trim();
    if (value) return value;
  }
  return undefined;
}

export function isConfigured(def: ProviderDefinition, env?: Record<string, string | undefined>): boolean {
  return def.auth.type !== "required" || Boolean(readApiKey(def, env));
}

const SENSITIVE_KEY = /(api[-_]?key|apikey|token|secret|password|passwd|authorization|auth[-_]?key|cookie|session)/i;
const MAX_RAW_BYTES = 300_000;

/** Removes anything credential-shaped and bounds the stored size. */
export function sanitizeRaw(raw: unknown): unknown {
  if (raw === undefined) return undefined;
  let json: string;
  try {
    json = JSON.stringify(raw, (key, value) => (key && SENSITIVE_KEY.test(key) ? "[redacted]" : value));
  } catch {
    return { note: "Raw payload could not be serialised" };
  }
  if (json === undefined) return undefined;
  if (json.length > MAX_RAW_BYTES) {
    return { note: `Raw payload omitted from storage: ${json.length.toLocaleString()} bytes exceeds the ${MAX_RAW_BYTES.toLocaleString()} byte limit` };
  }
  return JSON.parse(json);
}

/** Describes a request without secrets: method, host, path template and query keys. */
export function describeEndpoint(url: string, method: string, observable: string): string {
  try {
    const u = new URL(url);
    const encoded = encodeURIComponent(observable);
    const path = u.pathname.split(encoded).join("{value}").split(observable).join("{value}");
    const keys = [...u.searchParams.keys()];
    return `${method} ${u.host}${path}${keys.length ? `?${keys.join("&")}` : ""}`;
  } catch {
    return method;
  }
}

interface Classified {
  status: ProviderStatus;
  errorType: string;
  errorMessage: string;
  httpStatus?: number;
}

export function classifyError(err: unknown, def: ProviderDefinition, keySent = def.auth.type === "required"): Classified {
  if (err instanceof ProviderSkip) return { status: "SKIPPED", errorType: "not-applicable", errorMessage: err.message };

  if (err instanceof ProviderRequestError) {
    switch (err.kind) {
      case "timeout":
      case "aborted":
        return { status: "TIMEOUT", errorType: "timeout", errorMessage: `${def.name} did not respond within ${Math.round(def.timeoutMs / 1000)}s.` };
      case "invalid-json":
        return { status: "INVALID_RESPONSE", errorType: "invalid-json", errorMessage: err.message, httpStatus: err.status };
      case "schema":
        return { status: "INVALID_RESPONSE", errorType: "schema-mismatch", errorMessage: err.message, httpStatus: err.status };
      case "too-large":
        return { status: "INVALID_RESPONSE", errorType: "response-too-large", errorMessage: err.message };
      case "policy":
        return { status: "UNAVAILABLE", errorType: "blocked-by-policy", errorMessage: err.message };
      case "network":
        return { status: "NETWORK_ERROR", errorType: "network", errorMessage: `Could not reach ${def.name}: ${err.message}` };
      case "http": {
        const s = err.status ?? 0;
        if (s === 401 || s === 403) {
          return def.auth.type === "none" || !keySent
            ? { status: "UNAVAILABLE", errorType: "access-denied", httpStatus: s, errorMessage: `${def.name} refused the request (HTTP ${s}). Access may be blocked from this network.` }
            : { status: "AUTH_FAILED", errorType: "auth-failed", httpStatus: s, errorMessage: `${def.name} rejected the credentials (HTTP ${s}). Check the configured API key.` };
        }
        if (s === 429) {
          const wait = err.retryAfterSeconds ? ` Retry after ${err.retryAfterSeconds}s.` : "";
          return { status: "RATE_LIMITED", errorType: "rate-limited", httpStatus: s, errorMessage: `${def.name} is rate limiting requests.${wait}` };
        }
        if (s >= 500) return { status: "UNAVAILABLE", errorType: "upstream-error", httpStatus: s, errorMessage: `${def.name} returned a server error (HTTP ${s}).` };
        return { status: "INVALID_RESPONSE", errorType: "upstream-rejected", httpStatus: s, errorMessage: `${def.name} rejected the request (HTTP ${s}).` };
      }
    }
  }

  if (err instanceof TargetRequestError) {
    if (err.kind === "policy") return { status: "SKIPPED", errorType: "blocked-by-policy", errorMessage: `Not inspected: ${err.message}` };
    if (err.kind === "timeout") return { status: "TIMEOUT", errorType: "timeout", errorMessage: err.message };
    if (err.kind === "tls") return { status: "NETWORK_ERROR", errorType: "tls", errorMessage: err.message };
    return { status: "NETWORK_ERROR", errorType: err.kind, errorMessage: err.message };
  }

  if (err instanceof NetworkPolicyError) return { status: "SKIPPED", errorType: "blocked-by-policy", errorMessage: `Not inspected: ${err.message}` };

  const e = err as NodeJS.ErrnoException;
  if (e?.name === "TimeoutError" || e?.name === "AbortError") {
    return { status: "TIMEOUT", errorType: "timeout", errorMessage: `${def.name} did not complete within ${Math.round(def.timeoutMs / 1000)}s.` };
  }
  if (e?.code && /^(ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH)$/.test(e.code)) {
    return { status: "NETWORK_ERROR", errorType: "network", errorMessage: `${e.code}: ${e.message}` };
  }
  return { status: "UNAVAILABLE", errorType: "internal-error", errorMessage: `${def.name} analysis failed unexpectedly.` };
}

function cacheKey(input: ExecuteInput): string {
  return `${input.type}:${input.observable}:${input.mode}`;
}

export async function executeProvider(def: ProviderDefinition, input: ExecuteInput, services: RuntimeServices = {}): Promise<ProviderOutcome> {
  const env = services.env ?? process.env;
  const startedAt = new Date();
  const base = { provider: def.id, startedAt: startedAt.toISOString() };
  const finish = (partial: Omit<ProviderOutcome, "provider" | "latencyMs" | "retrievedAt">): ProviderOutcome => ({
    ...base,
    latencyMs: Date.now() - startedAt.getTime(),
    retrievedAt: new Date().toISOString(),
    ...partial,
  });

  const skipReason = def.skip?.({ observable: input.observable, type: input.type });
  if (skipReason) return finish({ status: "SKIPPED", errorType: "not-applicable", errorMessage: skipReason });

  const apiKey = readApiKey(def, env);
  if (def.auth.type === "required" && !apiKey) {
    return finish({
      status: "NOT_CONFIGURED",
      errorType: "not-configured",
      errorMessage: `Set ${def.auth.env[0]} to enable ${def.name}.`,
    });
  }

  const cacheable = def.cacheTtlSeconds > 0 && def.kind !== "derived" && Boolean(services.cache);
  if (cacheable && !input.fresh) {
    try {
      const hit = await services.cache!.get(def.id, cacheKey(input));
      if (hit) return { ...hit, provider: def.id, cached: true, latencyMs: 0, startedAt: startedAt.toISOString() };
    } catch (err) {
      services.logger?.("cache read failed", { provider: def.id, error: (err as Error).message });
    }
  }

  const quotas = typeof def.quotas === "function" ? def.quotas({ hasKey: Boolean(apiKey) }) : def.quotas ?? [];
  if (quotas.length && services.quota) {
    for (const q of quotas) {
      const allowed = await services.quota.consume(`provider:${def.id}:${q.windowSeconds}`, q.limit, q.windowSeconds).catch(() => true);
      if (!allowed) {
        return finish({
          status: "RATE_LIMITED",
          errorType: "local-quota",
          errorMessage: `Skipped to stay within ${def.name}'s ${q.label}. It will be available again shortly.`,
        });
      }
    }
  }

  const diagnostics: ProviderDiagnostics = { requests: 0, validation: "not-applicable" };
  const timeout = AbortSignal.timeout(def.timeoutMs);
  const signal = input.signal ? AbortSignal.any([input.signal, timeout]) : timeout;

  const ctx: ProviderRunContext = {
    observable: input.observable,
    type: input.type,
    mode: input.mode,
    signal,
    apiKey,
    dependencies: input.dependencies ?? new Map(),
    describe(id) {
      const d = services.catalog?.(id);
      return d ? { id: d.id, name: d.name, vendor: d.vendor, category: d.category, kind: d.kind } : undefined;
    },
    async json(url, schema, options = {}) {
      diagnostics.endpoint ??= describeEndpoint(url, options.method ?? "GET", input.observable);
      try {
        const result = await providerJson(url, schema, { timeoutMs: def.timeoutMs, ...options, signal });
        diagnostics.requests = (diagnostics.requests ?? 0) + result.response.requests;
        diagnostics.bytes = (diagnostics.bytes ?? 0) + result.response.bytes;
        diagnostics.validation = "passed";
        return result;
      } catch (err) {
        diagnostics.requests = (diagnostics.requests ?? 0) + 1;
        if (err instanceof ProviderRequestError && (err.kind === "schema" || err.kind === "invalid-json")) diagnostics.validation = "failed";
        throw err;
      }
    },
    async request(url, options = {}) {
      diagnostics.endpoint ??= describeEndpoint(url, options.method ?? "GET", input.observable);
      const response = await providerRequest(url, { timeoutMs: def.timeoutMs, ...options, signal });
      diagnostics.requests = (diagnostics.requests ?? 0) + response.requests;
      diagnostics.bytes = (diagnostics.bytes ?? 0) + response.bytes;
      return response;
    },
    parse(response, schema) {
      try {
        const value = parseProviderJson(response.text, schema, response.status);
        diagnostics.validation = "passed";
        return value;
      } catch (err) {
        diagnostics.validation = "failed";
        throw err;
      }
    },
    note(message) {
      diagnostics.note = diagnostics.note ? `${diagnostics.note}; ${message}` : message;
    },
  };

  let result: ProviderRunResult;
  try {
    result = await def.run(ctx);
  } catch (err) {
    const classified = classifyError(err, def, Boolean(apiKey));
    if (classified.errorType === "internal-error") {
      services.logger?.("provider failed", { provider: def.id, error: (err as Error)?.message, stack: (err as Error)?.stack?.split("\n").slice(0, 4).join(" | ") });
    }
    return finish({ ...classified, diagnostics });
  }

  const { raw, empty, partial, ...normalized } = result;
  const outcome = finish({
    status: empty ? "EMPTY" : partial ? "PARTIAL" : "SUCCESS",
    result: normalized,
    raw: sanitizeRaw(raw),
    diagnostics,
  });

  if (cacheable && (outcome.status === "SUCCESS" || outcome.status === "EMPTY")) {
    services.cache!.set(def.id, cacheKey(input), outcome, def.cacheTtlSeconds).catch((err) => {
      services.logger?.("cache write failed", { provider: def.id, error: (err as Error).message });
    });
  }
  return outcome;
}
