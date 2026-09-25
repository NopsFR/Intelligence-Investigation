import { requestJson, timed, successOutcome, failureOutcome, notConfiguredOutcome } from "./base";
import { virusTotalResponseSchema } from "@/lib/validation/schemas";
import { getEnv } from "./env";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"];

function endpointFor(observable: string, type: ObservableType): string {
  const base = "https://www.virustotal.com/api/v3";
  switch (type) {
    case "IPV4":
    case "IPV6":
      return `${base}/ip_addresses/${encodeURIComponent(observable)}`;
    case "DOMAIN":
      return `${base}/domains/${encodeURIComponent(observable)}`;
    case "URL": {
      const id = Buffer.from(observable).toString("base64url").replace(/=+$/, "");
      return `${base}/urls/${id}`;
    }
    case "MD5":
    case "SHA1":
    case "SHA256":
      return `${base}/files/${encodeURIComponent(observable)}`;
    default:
      throw new Error("Unsupported observable type for VirusTotal");
  }
}

interface VtStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

export const virusTotalProvider: Provider = {
  meta: {
    id: "virustotal",
    name: "VirusTotal",
    description: "Multi-engine reputation and detection data for IPs, domains, URLs, and file hashes.",
    availability: "quota-limited",
    homepage: "https://www.virustotal.com",
    supports: SUPPORTED,
    requiresEnv: ["VIRUSTOTAL_API_KEY"],
  },
  isConfigured: () => Boolean(getEnv("VIRUSTOTAL_API_KEY")),
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const apiKey = getEnv("VIRUSTOTAL_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const { result, latencyMs } = await timed(() =>
        requestJson(endpointFor(ctx.observable, ctx.type), virusTotalResponseSchema, {
          headers: { "x-apikey": apiKey },
        })
      );

      const attrs = result.data.attributes;
      const stats = attrs.last_analysis_stats as VtStats | undefined;
      const reputation = attrs.reputation as number | undefined;
      const malicious = stats?.malicious ?? 0;
      const suspicious = stats?.suspicious ?? 0;
      const totalEngines = (stats?.malicious ?? 0) + (stats?.suspicious ?? 0) + (stats?.harmless ?? 0) + (stats?.undetected ?? 0);

      const findings =
        malicious > 0
          ? [
              {
                severity: (malicious >= 10 ? "CRITICAL" : malicious >= 3 ? "HIGH" : "MEDIUM") as
                  | "CRITICAL"
                  | "HIGH"
                  | "MEDIUM",
                category: "reputation",
                title: `Flagged malicious by ${malicious} of ${totalEngines} VirusTotal engines`,
                description: "One or more security vendors classify this observable as malicious.",
                evidence: `VirusTotal last analysis: ${malicious} malicious, ${suspicious} suspicious, ${stats?.harmless ?? 0} harmless, ${stats?.undetected ?? 0} undetected (${totalEngines} engines total).`,
              },
            ]
          : [];

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: totalEngines ? `${malicious}/${totalEngines} engines flagged as malicious` : "No analysis data",
          fields: {
            reputation,
            malicious,
            suspicious,
            harmless: stats?.harmless,
            undetected: stats?.undetected,
            totalEngines,
            lastAnalysisDate: attrs.last_analysis_date,
            categories: attrs.categories,
            fileType: attrs.type_description,
            fileSize: attrs.size,
            magic: attrs.magic,
          },
          findings,
        },
        { id: result.data.id, type: result.data.type }
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    const apiKey = getEnv("VIRUSTOTAL_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const { latencyMs } = await timed(() =>
        requestJson("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1", virusTotalResponseSchema, {
          headers: { "x-apikey": apiKey },
        })
      );
      return successOutcome(this.meta.id, latencyMs, { summary: "VirusTotal reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
};
