import { requestJson, timed, successOutcome, failureOutcome } from "./base";
import { nvdCveResponseSchema } from "@/lib/validation/schemas";
import { getEnv } from "./env";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["CVE"];

function extractCvss(metrics: Record<string, unknown> | undefined): { score?: number; vector?: string; version?: string } {
  if (!metrics) return {};
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const entries = metrics[key] as Array<{ cvssData?: { baseScore?: number; vectorString?: string; version?: string } }> | undefined;
    if (entries?.length) {
      const data = entries[0].cvssData;
      return { score: data?.baseScore, vector: data?.vectorString, version: data?.version };
    }
  }
  return {};
}

export const nvdProvider: Provider = {
  meta: {
    id: "nvd",
    name: "NVD",
    description: "NIST National Vulnerability Database — CVE descriptions, CVSS scoring, and CWE classification.",
    availability: "no-key",
    homepage: "https://nvd.nist.gov",
    supports: SUPPORTED,
  },
  isConfigured: () => true,
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const start = Date.now();
    try {
      const apiKey = getEnv("NVD_API_KEY");
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(ctx.observable)}`;
      const { result, latencyMs } = await timed(() =>
        requestJson(url, nvdCveResponseSchema, {
          timeoutMs: 10000,
          headers: apiKey ? { apiKey } : undefined,
        })
      );

      const vuln = result.vulnerabilities?.[0]?.cve;
      if (!vuln) {
        return successOutcome(this.meta.id, latencyMs, { summary: "No result", fields: {} });
      }

      const description = vuln.descriptions?.find((d) => d.lang === "en")?.value;
      const cvss = extractCvss(vuln.metrics);
      const cwes = (vuln.weaknesses as Array<{ description?: { value?: string }[] }> | undefined)
        ?.flatMap((w) => w.description ?? [])
        .map((d) => d.value)
        .filter(Boolean);
      const references = (vuln.references as Array<{ url?: string }> | undefined)
        ?.map((r) => r.url)
        .filter((u): u is string => Boolean(u));

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: description ?? vuln.id,
          fields: {
            id: vuln.id,
            description,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssVersion: cvss.version,
            cwes,
            published: vuln.published,
            lastModified: vuln.lastModified,
          },
          links: references?.slice(0, 10).map((u) => ({ label: u, url: u })),
        },
        vuln
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    const start = Date.now();
    try {
      const apiKey = getEnv("NVD_API_KEY");
      const { latencyMs } = await timed(() =>
        requestJson(
          "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
          nvdCveResponseSchema,
          { timeoutMs: 10000, headers: apiKey ? { apiKey } : undefined }
        )
      );
      return successOutcome(this.meta.id, latencyMs, { summary: "NVD reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
};
