import { requestJson, timed, successOutcome, failureOutcome, notConfiguredOutcome } from "./base";
import { urlhausResponseSchema } from "@/lib/validation/schemas";
import { getEnv } from "./env";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["URL", "DOMAIN", "IPV4", "IPV6"];

function endpointFor(type: ObservableType): { url: string; field: string } {
  if (type === "URL") return { url: "https://urlhaus-api.abuse.ch/v1/url/", field: "url" };
  return { url: "https://urlhaus-api.abuse.ch/v1/host/", field: "host" };
}

export const urlhausProvider: Provider = {
  meta: {
    id: "urlhaus",
    name: "URLhaus",
    description: "abuse.ch malicious URL and payload distribution tracking.",
    availability: "free-registration",
    homepage: "https://urlhaus.abuse.ch",
    supports: SUPPORTED,
    requiresEnv: ["URLHAUS_API_KEY"],
  },
  isConfigured: () => Boolean(getEnv("URLHAUS_API_KEY")),
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const apiKey = getEnv("URLHAUS_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const { url, field } = endpointFor(ctx.type);
      const { result, latencyMs } = await timed(() =>
        requestJson(url, urlhausResponseSchema, {
          method: "POST",
          headers: { "Auth-Key": apiKey, "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ [field]: ctx.observable }).toString(),
        })
      );

      if (result.query_status !== "ok") {
        return successOutcome(this.meta.id, latencyMs, { summary: "No result", fields: {} });
      }

      const findings =
        result.url_status || result.threat
          ? [
              {
                severity: "HIGH" as const,
                category: "threat-intelligence",
                title: `Listed on URLhaus (${result.threat ?? "malicious URL"})`,
                description: "This observable is tracked by URLhaus as associated with malware distribution.",
                evidence: `Status: ${result.url_status ?? "unknown"}. Threat type: ${result.threat ?? "unreported"}.`,
              },
            ]
          : [];

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: result.threat ? `Threat: ${result.threat}` : "No active threat listed",
          fields: {
            urlStatus: result.url_status,
            threat: result.threat,
            tags: result.tags,
            payloadCount: result.payloads?.length ?? 0,
          },
          findings,
        },
        result
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    const apiKey = getEnv("URLHAUS_API_KEY");
    if (!apiKey) return notConfiguredOutcome(this.meta.id);

    const start = Date.now();
    try {
      const { latencyMs } = await timed(() =>
        requestJson("https://urlhaus-api.abuse.ch/v1/host/", urlhausResponseSchema, {
          method: "POST",
          headers: { "Auth-Key": apiKey, "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ host: "example.com" }).toString(),
        })
      );
      return successOutcome(this.meta.id, latencyMs, { summary: "URLhaus reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
};
