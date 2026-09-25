import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:dns/promises", () => ({
  default: {
    lookup: vi.fn().mockResolvedValue([{ address: "1.1.1.1", family: 4 }]),
  },
}));

import { abuseIpDbProvider } from "./abuseipdb";

const ctx = { observable: "1.2.3.4", type: "IPV4" as const, signal: new AbortController().signal };

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

describe("abuseIpDbProvider", () => {
  const originalEnv = process.env.ABUSEIPDB_API_KEY;

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    process.env.ABUSEIPDB_API_KEY = originalEnv;
  });

  it("reports NOT_CONFIGURED when no API key is set", async () => {
    delete process.env.ABUSEIPDB_API_KEY;
    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("NOT_CONFIGURED");
  });

  it("returns SUCCESS with normalized fields and a finding for a positive abuse score", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse(200, {
        data: {
          ipAddress: "1.2.3.4",
          abuseConfidenceScore: 75,
          countryCode: "US",
          isp: "Example ISP",
          domain: "example.com",
          usageType: "Data Center",
          totalReports: 12,
          lastReportedAt: "2026-01-01T00:00:00Z",
          isTor: false,
        },
      })
    );

    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("SUCCESS");
    expect(outcome.normalized?.fields.abuseConfidenceScore).toBe(75);
    expect(outcome.normalized?.findings).toHaveLength(1);
    expect(outcome.normalized?.findings?.[0].severity).toBe("HIGH");
  });

  it("returns EMPTY (no findings) when the abuse score is zero", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      jsonResponse(200, {
        data: { ipAddress: "1.2.3.4", abuseConfidenceScore: 0 },
      })
    );

    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("SUCCESS");
    expect(outcome.normalized?.findings).toHaveLength(0);
  });

  it("classifies HTTP 401 as AUTH_FAILED", async () => {
    process.env.ABUSEIPDB_API_KEY = "bad-key";
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(new Response("", { status: 401 }));
    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("AUTH_FAILED");
  });

  it("classifies HTTP 429 as RATE_LIMITED", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(new Response("", { status: 429 }));
    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("RATE_LIMITED");
  });

  it("classifies HTTP 500 as UNAVAILABLE", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(new Response("", { status: 500 }));
    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("UNAVAILABLE");
  });

  it("classifies malformed JSON as INVALID_RESPONSE", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response("not json", { status: 200, headers: { "content-type": "application/json" } })
    );
    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("INVALID_RESPONSE");
  });

  it("classifies a response missing required fields as INVALID_RESPONSE", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue(jsonResponse(200, { data: { ipAddress: "1.2.3.4" } }));
    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("INVALID_RESPONSE");
  });

  it("classifies a network failure as NETWORK_ERROR", async () => {
    process.env.ABUSEIPDB_API_KEY = "test-key";
    (fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new TypeError("fetch failed"));
    const outcome = await abuseIpDbProvider.investigate(ctx);
    expect(outcome.status).toBe("NETWORK_ERROR");
  });
});
