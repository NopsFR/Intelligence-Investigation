import { requestJson, timed, successOutcome, failureOutcome, notConfiguredOutcome } from "./base";
import { threatFoxResponseSchema } from "@/lib/validation/schemas";
import { getEnv } from "./env";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"];
const ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/";

interface IocEntry {
  ioc?: string;
  threat_type?: string;
  malware?: string;
  malware_printable?: string;
  confidence_level?: number;
  first_seen?: string;
  last_seen?: string;
  tags?: string[] | null;
  reference?: string;
}

export const threatFoxProvider: Provider = {
  meta: {
    id: "threatfox",
    name: "ThreatFox",
    description: "abuse.ch IOC intelligence for IPs, domains, URLs, and hashes.",
    availability: "free-registration",
    homepage: "https://threatfox.abuse.ch",
    supports: SUPPORTED,
    requiresEnv: ["THREATFOX_API_KEY"],
  },
  isConfigured: () => Boolean(getEnv("THREATFOX_API_KEY")),
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const apiKey = getEnv("THREATFOX_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const { result, latencyMs } = await timed(() =>
        requestJson(ENDPOINT, threatFoxResponseSchema, {
          headers: { "Auth-Key": apiKey, "content-type": "application/json" },
          method: "POST",
          body: JSON.stringify({ query: "search_ioc", search_term: ctx.observable }),
        })
      );

      if (result.query_status !== "ok" || !Array.isArray(result.data)) {
        return successOutcome(this.meta.id, latencyMs, { summary: "No result", fields: {} });
      }

      const entries = result.data as unknown as IocEntry[];
      const findings = entries.slice(0, 5).map((e) => ({
        severity: "HIGH" as const,
        category: "threat-intelligence",
        title: `Associated with ${e.malware_printable ?? e.malware ?? "known malware infrastructure"}`,
        description: `Reported as ${e.threat_type ?? "an indicator of compromise"} by ThreatFox.`,
        evidence: `First seen ${e.first_seen ?? "unknown"}, last seen ${e.last_seen ?? "unknown"}. Confidence level: ${e.confidence_level ?? "unreported"}.`,
        confidence: e.confidence_level ? `${e.confidence_level}%` : undefined,
      }));

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: `${entries.length} ThreatFox IOC record(s) found`,
          fields: {
            recordCount: entries.length,
            malwareFamilies: Array.from(new Set(entries.map((e) => e.malware_printable ?? e.malware).filter(Boolean))),
            threatTypes: Array.from(new Set(entries.map((e) => e.threat_type).filter(Boolean))),
          },
          findings,
          links: entries.filter((e) => e.reference).slice(0, 5).map((e) => ({ label: "ThreatFox reference", url: e.reference! })),
        },
        entries.slice(0, 20)
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    const apiKey = getEnv("THREATFOX_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const { latencyMs } = await timed(() =>
        requestJson(ENDPOINT, threatFoxResponseSchema, {
          headers: { "Auth-Key": apiKey, "content-type": "application/json" },
          method: "POST",
          body: JSON.stringify({ query: "search_ioc", search_term: "1.1.1.1" }),
        })
      );
      return successOutcome(this.meta.id, latencyMs, { summary: "ThreatFox reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
};
