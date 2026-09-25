import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import type { ProviderOutcome } from "@/lib/core/types";
import { executeProvider, sanitizeRaw, type CacheStore, type QuotaStore } from "./runtime";
import type { ProviderDefinition } from "./types";

const schema = z.object({ data: z.object({ score: z.number() }) });

function def(overrides: Partial<ProviderDefinition> = {}): ProviderDefinition {
  return {
    id: "fake",
    code: "FK",
    name: "Fake Intel",
    vendor: "Test",
    category: "reputation",
    kind: "external",
    description: "",
    homepage: "https://fake.test",
    auth: { type: "none" },
    endpoint: "REST",
    supports: ["IPV4"],
    cacheTtlSeconds: 0,
    timeoutMs: 500,
    async run(ctx) {
      const res = await ctx.request(`https://api.fake.test/v1/ip/${ctx.observable}`, { acceptStatus: [404], retries: 0 });
      if (res.status === 404) return { summary: "Not found", facts: [], empty: true };
      const data = ctx.parse(res, schema);
      return { summary: `score ${data.data.score}`, facts: [{ key: "score", label: "Score", value: data.data.score }], raw: { ...data, apiKey: "should-not-persist" } };
    },
    ...overrides,
  };
}

const input = { observable: "198.51.100.7", type: "IPV4" as const, mode: "QUICK" as const };

function mockFetch(impl: (url: string, init?: RequestInit) => Promise<Response> | Response) {
  const fn = vi.fn(impl);
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("provider runtime: outcome classification", () => {
  it("SUCCESS with validated, normalised data and redacted raw payload", async () => {
    mockFetch(() => Response.json({ data: { score: 42 } }));
    const o = await executeProvider(def(), input);
    expect(o.status).toBe("SUCCESS");
    expect(o.result?.summary).toBe("score 42");
    expect(o.diagnostics?.validation).toBe("passed");
    expect(o.diagnostics?.endpoint).toBe("GET api.fake.test/v1/ip/{value}");
    expect(JSON.stringify(o.raw)).not.toContain("should-not-persist");
  });

  it("EMPTY when the source answers but has no record (404)", async () => {
    mockFetch(() => new Response("{}", { status: 404 }));
    expect((await executeProvider(def(), input)).status).toBe("EMPTY");
  });

  it("NOT_CONFIGURED without calling the network when a required key is missing", async () => {
    const f = mockFetch(() => Response.json({}));
    const o = await executeProvider(def({ auth: { type: "required", env: ["FAKE_KEY"], header: "x-key", signup: "https://fake.test" } }), input, { env: {} });
    expect(o.status).toBe("NOT_CONFIGURED");
    expect(o.errorMessage).toContain("FAKE_KEY");
    expect(f).not.toHaveBeenCalled();
  });

  it.each([
    [401, "required", "AUTH_FAILED"],
    [403, "required", "AUTH_FAILED"],
    [403, "none", "UNAVAILABLE"],
    [429, "none", "RATE_LIMITED"],
    [500, "none", "UNAVAILABLE"],
    [503, "none", "UNAVAILABLE"],
    [400, "none", "INVALID_RESPONSE"],
  ] as const)("HTTP %i with auth=%s → %s", async (status, auth, expected) => {
    mockFetch(() => new Response("nope", { status, headers: status === 429 ? { "retry-after": "30" } : {} }));
    const d = auth === "required" ? def({ auth: { type: "required", env: ["FAKE_KEY"], header: "x-key", signup: "https://fake.test" } }) : def();
    const o = await executeProvider(d, input, { env: { FAKE_KEY: "k" } });
    expect(o.status).toBe(expected);
    expect(o.httpStatus).toBe(status);
    if (status === 429) expect(o.errorMessage).toContain("30s");
  });

  it("an optional-key provider rejected without a key is unavailable, not an auth failure", async () => {
    mockFetch(() => new Response("forbidden", { status: 403 }));
    const o = await executeProvider(def({ auth: { type: "optional", env: ["FAKE_KEY"], header: "x-key", signup: "https://fake.test", benefit: "" } }), input, { env: {} });
    expect(o.status).toBe("UNAVAILABLE");
  });

  it("INVALID_RESPONSE for malformed JSON and for schema mismatches", async () => {
    mockFetch(() => new Response("<html>oops</html>", { status: 200 }));
    const bad = await executeProvider(def(), input);
    expect(bad.status).toBe("INVALID_RESPONSE");
    expect(bad.errorType).toBe("invalid-json");
    mockFetch(() => Response.json({ data: { score: "high" } }));
    const mismatch = await executeProvider(def(), input);
    expect(mismatch.status).toBe("INVALID_RESPONSE");
    expect(mismatch.errorType).toBe("schema-mismatch");
    expect(mismatch.diagnostics?.validation).toBe("failed");
  });

  it("NETWORK_ERROR when the host cannot be reached", async () => {
    mockFetch(() => Promise.reject(Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } })));
    const o = await executeProvider(def(), input);
    expect(o.status).toBe("NETWORK_ERROR");
    expect(o.errorMessage).toContain("ECONNREFUSED");
  });

  it("TIMEOUT when the provider does not answer in time", async () => {
    mockFetch((_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))));
    const o = await executeProvider(def({ timeoutMs: 50 }), input);
    expect(o.status).toBe("TIMEOUT");
  });

  it("PARTIAL results stay usable", async () => {
    const o = await executeProvider(def({ run: async () => ({ summary: "half", facts: [], partial: true }) }), input);
    expect(o.status).toBe("PARTIAL");
    expect(o.result?.summary).toBe("half");
  });

  it("SKIPPED when the provider declines the input", async () => {
    const o = await executeProvider(def({ skip: () => "not relevant" }), input);
    expect(o.status).toBe("SKIPPED");
    expect(o.errorMessage).toBe("not relevant");
  });

  it("internal bugs become a generic UNAVAILABLE without leaking details", async () => {
    const logger = vi.fn();
    const o = await executeProvider(def({ run: async () => { throw new Error("secret stack detail"); } }), input, { logger });
    expect(o.status).toBe("UNAVAILABLE");
    expect(o.errorMessage).not.toContain("secret");
    expect(logger).toHaveBeenCalled();
  });
});

describe("provider runtime: cache and quotas", () => {
  it("serves cached answers and bypasses the cache when fresh", async () => {
    const store = new Map<string, ProviderOutcome>();
    const cache: CacheStore = {
      get: async (p, k) => store.get(`${p}|${k}`) ?? null,
      set: async (p, k, o) => void store.set(`${p}|${k}`, o),
    };
    const f = mockFetch(() => Response.json({ data: { score: 7 } }));
    const d = def({ cacheTtlSeconds: 60 });
    await executeProvider(d, input, { cache });
    await new Promise((r) => setTimeout(r, 0));
    const second = await executeProvider(d, input, { cache });
    expect(second.cached).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
    await executeProvider(d, { ...input, fresh: true }, { cache });
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("refuses to exceed a local quota", async () => {
    const f = mockFetch(() => Response.json({ data: { score: 1 } }));
    const quota: QuotaStore = { consume: async () => false };
    const o = await executeProvider(def({ quotas: [{ limit: 4, windowSeconds: 60, label: "4 requests per minute" }] }), input, { quota });
    expect(o.status).toBe("RATE_LIMITED");
    expect(o.errorType).toBe("local-quota");
    expect(f).not.toHaveBeenCalled();
  });
});

describe("raw payload sanitising", () => {
  it("redacts credential-like keys and caps size", () => {
    expect(sanitizeRaw({ a: 1, Authorization: "Bearer x", nested: { api_key: "k", password: "p" } })).toEqual({ a: 1, Authorization: "[redacted]", nested: { api_key: "[redacted]", password: "[redacted]" } });
    const big = sanitizeRaw({ blob: "x".repeat(400_000) }) as { note: string };
    expect(big.note).toMatch(/omitted/);
  });
});
