import { describe, expect, it } from "vitest";
import type { NormalizedFinding, ProviderOutcome, Severity } from "@/lib/core/types";
import { executeProvider } from "../runtime";
import { getProvider } from "../registry";
import { correlation } from "./correlation";

function outcome(provider: string, findings: Partial<NormalizedFinding>[] = [], status: ProviderOutcome["status"] = "SUCCESS", data?: Record<string, unknown>): [string, ProviderOutcome] {
  return [
    provider,
    {
      provider,
      status,
      latencyMs: 1,
      retrievedAt: new Date().toISOString(),
      result: { summary: "", facts: [], data: data ? { kind: "x", ...data } : undefined, findings: findings.map((f) => ({ rule: "x", severity: "INFO" as Severity, category: "t", title: f.rule ?? "t", description: "", evidence: "", ...f })) },
    },
  ];
}

async function run(type: "IPV4" | "CVE", deps: [string, ProviderOutcome][]) {
  const o = await executeProvider(correlation, { observable: type === "CVE" ? "CVE-2021-44228" : "198.51.100.7", type, mode: "QUICK", dependencies: new Map(deps) }, { catalog: getProvider });
  return { o, rules: (o.result?.findings ?? []).map((f) => f.rule) };
}

describe("cross-source correlation", () => {
  it("corroboration requires independent organisations, not several feeds from one vendor", async () => {
    const sameVendor = await run("IPV4", [outcome("threatfox", [{ rule: "intel.threatfox.listed", severity: "HIGH" }]), outcome("feodo", [{ rule: "intel.feodo.c2-online", severity: "CRITICAL" }]), outcome("otx"), outcome("greynoise")]);
    expect(sameVendor.rules).not.toContain("correlation.corroborated");
    expect(sameVendor.rules).toContain("correlation.single-source");

    const independent = await run("IPV4", [outcome("threatfox", [{ rule: "intel.threatfox.listed", severity: "HIGH" }]), outcome("abuseipdb", [{ rule: "reputation.abuseipdb.confidence", severity: "MEDIUM" }])]);
    expect(independent.rules).toContain("correlation.corroborated");
    expect(independent.o.result?.findings?.find((f) => f.rule === "correlation.corroborated")?.severity).toBe("HIGH");
  });

  it("reports contradictions between adverse and benign sources", async () => {
    const r = await run("IPV4", [outcome("abuseipdb", [{ rule: "reputation.abuseipdb.confidence", severity: "HIGH" }]), outcome("greynoise", [{ rule: "reputation.greynoise.riot", severity: "INFO" }])]);
    expect(r.rules).toContain("correlation.conflict");
  });

  it("low-severity mentions are not treated as adverse", async () => {
    const r = await run("IPV4", [outcome("otx", [{ rule: "intel.otx.pulses", severity: "LOW" }]), outcome("greynoise"), outcome("internetdb"), outcome("feodo", [], "EMPTY")]);
    expect(r.rules).toContain("correlation.no-adverse-intel");
  });

  it("is EMPTY when no source answered", async () => {
    const r = await run("IPV4", [outcome("otx", [], "TIMEOUT"), outcome("greynoise", [], "NETWORK_ERROR")]);
    expect(r.o.status).toBe("EMPTY");
  });

  it("chooses the NVD primary CVSS score over CNA and ADP", async () => {
    const r = await run("CVE", [
      outcome("nvd", [], "SUCCESS", { metrics: [{ source: "nvd@nist.gov", type: "Primary", baseScore: 10, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", version: "3.1" }] }),
      outcome("cve-org", [], "SUCCESS", { cnaCvss: { baseScore: 9.1, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", version: "3.1" }, assigner: "apache" }),
    ]);
    const f = r.o.result?.findings?.find((x) => x.rule === "vuln.cvss");
    expect(f?.severity).toBe("CRITICAL");
    expect(f?.description).toMatch(/NVD primary/);
    expect(f?.description).toMatch(/disagree/);
  });
});
