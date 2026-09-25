import { requestJson, timed, successOutcome, failureOutcome, notConfiguredOutcome } from "./base";
import { abuseIpDbResponseSchema } from "@/lib/validation/schemas";
import { getEnv } from "./env";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["IPV4", "IPV6"];

function severityForScore(score: number): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  if (score >= 90) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 25) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFO";
}

export const abuseIpDbProvider: Provider = {
  meta: {
    id: "abuseipdb",
    name: "AbuseIPDB",
    description: "Community-reported IP abuse confidence scoring, ISP, and usage-type data.",
    availability: "free-registration",
    homepage: "https://www.abuseipdb.com",
    supports: SUPPORTED,
    requiresEnv: ["ABUSEIPDB_API_KEY"],
  },
  isConfigured: () => Boolean(getEnv("ABUSEIPDB_API_KEY")),
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const apiKey = getEnv("ABUSEIPDB_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ctx.observable)}&maxAgeInDays=90`;
      const { result, latencyMs } = await timed(() =>
        requestJson(url, abuseIpDbResponseSchema, {
          headers: { Key: apiKey, Accept: "application/json" },
        })
      );

      const d = result.data;
      const findings =
        d.abuseConfidenceScore > 0
          ? [
              {
                severity: severityForScore(d.abuseConfidenceScore),
                category: "reputation",
                title: `AbuseIPDB confidence score: ${d.abuseConfidenceScore}%`,
                description: `${d.totalReports ?? 0} report(s) submitted against this IP within the last 90 days.`,
                evidence: `Abuse confidence score of ${d.abuseConfidenceScore}% based on ${d.totalReports ?? 0} community report(s). Last reported: ${d.lastReportedAt ?? "unknown"}.`,
              },
            ]
          : [];

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: `Abuse confidence score: ${d.abuseConfidenceScore}%`,
          fields: {
            abuseConfidenceScore: d.abuseConfidenceScore,
            countryCode: d.countryCode,
            isp: d.isp,
            domain: d.domain,
            usageType: d.usageType,
            totalReports: d.totalReports,
            lastReportedAt: d.lastReportedAt,
            isTor: d.isTor,
          },
          findings,
        },
        d
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    const apiKey = getEnv("ABUSEIPDB_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const { latencyMs } = await timed(() =>
        requestJson("https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1", abuseIpDbResponseSchema, {
          headers: { Key: apiKey, Accept: "application/json" },
        })
      );
      return successOutcome(this.meta.id, latencyMs, { summary: "AbuseIPDB reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
};
