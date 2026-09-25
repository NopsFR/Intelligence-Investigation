import { requestJson, timed, successOutcome, failureOutcome } from "./base";
import { crtShResponseSchema } from "@/lib/validation/schemas";
import { normalizeCertName } from "@/lib/observables/normalize";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["DOMAIN"];

export const crtShProvider: Provider = {
  meta: {
    id: "crtsh",
    name: "crt.sh",
    description: "Certificate Transparency log search — discovers certificate-issued names for a domain.",
    availability: "no-key",
    homepage: "https://crt.sh",
    supports: SUPPORTED,
  },
  isConfigured: () => true,
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const start = Date.now();
    try {
      const url = `https://crt.sh/?q=${encodeURIComponent(`%.${ctx.observable}`)}&output=json`;
      const { result, latencyMs } = await timed(() =>
        requestJson(url, crtShResponseSchema, { timeoutMs: 12000 })
      );

      const names = new Set<string>();
      for (const entry of result) {
        for (const raw of entry.name_value.split("\n")) {
          const normalized = normalizeCertName(raw);
          if (normalized && (normalized === ctx.observable || normalized.endsWith(`.${ctx.observable}`))) {
            names.add(normalized);
          }
        }
      }

      const sortedNames = Array.from(names).sort();
      const relationships = sortedNames
        .filter((n) => n !== ctx.observable)
        .map((n) => ({
          sourceNode: ctx.observable,
          targetNode: n,
          relationType: "certificate_subject_alternative_name",
          evidence: "Observed in a Certificate Transparency log entry for this domain.",
        }));

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: `${sortedNames.length} certificate-associated name${sortedNames.length === 1 ? "" : "s"} found`,
          fields: {
            certificateCount: result.length,
            names: sortedNames,
            note: "Certificate Transparency enumeration is not an exhaustive subdomain list — only names covered by an issued, logged certificate appear here.",
          },
          relationships,
        },
        result.slice(0, 50)
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    const start = Date.now();
    try {
      const { latencyMs } = await timed(() =>
        requestJson("https://crt.sh/?q=example.com&output=json", crtShResponseSchema, { timeoutMs: 12000 })
      );
      return successOutcome(this.meta.id, latencyMs, { summary: "crt.sh reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
};
