import { describe, expect, it } from "vitest";
import { collectFindings } from "./engine";
import type { ProviderOutcome } from "@/types/provider";

function outcome(overrides: Partial<ProviderOutcome>): ProviderOutcome {
  return {
    provider: "test-provider",
    status: "SUCCESS",
    latencyMs: 10,
    retrievedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe("collectFindings", () => {
  it("returns an empty list when no provider emitted findings", () => {
    const results = collectFindings([outcome({ normalized: { summary: "ok", fields: {} } })]);
    expect(results).toHaveLength(0);
  });

  it("collects findings and attributes them to their source provider", () => {
    const results = collectFindings([
      outcome({
        provider: "abuseipdb",
        normalized: {
          summary: "x",
          fields: {},
          findings: [
            {
              severity: "HIGH",
              category: "reputation",
              title: "Test finding",
              description: "desc",
              evidence: "evidence",
            },
          ],
        },
      }),
    ]);
    expect(results).toHaveLength(1);
    expect(results[0].source).toBe("abuseipdb");
    expect(results[0].severity).toBe("HIGH");
  });

  it("sorts findings by severity, most severe first", () => {
    const results = collectFindings([
      outcome({
        normalized: {
          summary: "x",
          fields: {},
          findings: [
            { severity: "LOW", category: "c", title: "low", description: "d", evidence: "e" },
            { severity: "CRITICAL", category: "c", title: "critical", description: "d", evidence: "e" },
            { severity: "MEDIUM", category: "c", title: "medium", description: "d", evidence: "e" },
          ],
        },
      }),
    ]);
    expect(results.map((r) => r.severity)).toEqual(["CRITICAL", "MEDIUM", "LOW"]);
  });

  it("ignores providers with no normalized result (failures)", () => {
    const results = collectFindings([outcome({ status: "TIMEOUT", normalized: undefined })]);
    expect(results).toHaveLength(0);
  });
});
