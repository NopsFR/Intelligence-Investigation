import { describe, expect, it } from "vitest";
import { buildRelationships } from "./engine";
import type { ProviderOutcome } from "@/types/provider";

describe("buildRelationships", () => {
  it("returns no edges when no provider reports relationships", () => {
    const result = buildRelationships("example.com", [
      { provider: "rdap", status: "SUCCESS", latencyMs: 1, retrievedAt: new Date().toISOString() },
    ]);
    expect(result).toHaveLength(0);
  });

  it("converts provider-reported relationships into edges with provenance", () => {
    const outcomes: ProviderOutcome[] = [
      {
        provider: "crtsh",
        status: "SUCCESS",
        latencyMs: 1,
        retrievedAt: new Date().toISOString(),
        normalized: {
          summary: "x",
          fields: {},
          relationships: [
            {
              sourceNode: "example.com",
              targetNode: "api.example.com",
              relationType: "certificate_subject_alternative_name",
              evidence: "Observed in CT log",
            },
          ],
        },
      },
    ];
    const result = buildRelationships("example.com", outcomes);
    expect(result).toHaveLength(1);
    expect(result[0].sourceProvider).toBe("crtsh");
    expect(result[0].targetNode).toBe("api.example.com");
  });

  it("builds structural DNS resolution edges from DNS provider fields", () => {
    const outcomes: ProviderOutcome[] = [
      {
        provider: "cloudflare-dns",
        status: "SUCCESS",
        latencyMs: 1,
        retrievedAt: new Date().toISOString(),
        normalized: { summary: "x", fields: { A: ["93.184.216.34"], AAAA: [] } },
      },
    ];
    const result = buildRelationships("example.com", outcomes);
    expect(result).toHaveLength(1);
    expect(result[0].relationType).toBe("resolves_to_ipv4");
    expect(result[0].targetNode).toBe("93.184.216.34");
  });

  it("merges duplicate edges reported by more than one provider", () => {
    const shared = {
      sourceNode: "example.com",
      targetNode: "1.2.3.4",
      relationType: "resolves_to_ipv4",
      evidence: "shared",
    };
    const outcomes: ProviderOutcome[] = [
      {
        provider: "cloudflare-dns",
        status: "SUCCESS",
        latencyMs: 1,
        retrievedAt: new Date().toISOString(),
        normalized: { summary: "x", fields: {}, relationships: [shared] },
      },
      {
        provider: "google-dns",
        status: "SUCCESS",
        latencyMs: 1,
        retrievedAt: new Date().toISOString(),
        normalized: { summary: "x", fields: {}, relationships: [shared] },
      },
    ];
    const result = buildRelationships("example.com", outcomes);
    expect(result).toHaveLength(1);
    expect(result[0].sourceProvider).toContain("cloudflare-dns");
    expect(result[0].sourceProvider).toContain("google-dns");
  });
});
