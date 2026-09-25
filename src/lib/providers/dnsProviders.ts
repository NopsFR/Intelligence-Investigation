import { failureOutcome, successOutcome, timed } from "./base";
import { resolveViaCloudflare, resolveViaGoogle, type DnsRecordType } from "@/lib/dns/resolve";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["DOMAIN"];
const RECORD_TYPES: DnsRecordType[] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"];

function makeDnsProvider(id: string, name: string, resolver: typeof resolveViaCloudflare, homepage: string): Provider {
  return {
    meta: {
      id,
      name,
      description: `DNS-over-HTTPS resolution via ${name}.`,
      availability: "no-key",
      homepage,
      supports: SUPPORTED,
    },
    isConfigured: () => true,
    supports: (type) => SUPPORTED.includes(type),
    async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
      const start = Date.now();
      try {
        const { result: results, latencyMs } = await timed(() =>
          Promise.allSettled(RECORD_TYPES.map((t) => resolver(ctx.observable, t)))
        );

        const fields: Record<string, string[]> = {};
        let anyAnswer = false;
        for (let i = 0; i < RECORD_TYPES.length; i++) {
          const s = results[i];
          const type = RECORD_TYPES[i];
          if (s.status === "fulfilled") {
            const data = s.value.answers.map((a) => a.data);
            if (data.length) anyAnswer = true;
            fields[type] = data;
          }
        }

        return successOutcome(
          id,
          latencyMs,
          {
            summary: anyAnswer ? "DNS records resolved" : "No DNS records returned",
            fields,
          },
          fields
        );
      } catch (err) {
        return failureOutcome(id, Date.now() - start, err);
      }
    },
    async healthCheck(): Promise<ProviderOutcome> {
      const start = Date.now();
      try {
        const { latencyMs } = await timed(() => resolver("cloudflare.com", "A"));
        return successOutcome(id, latencyMs, { summary: `${name} reachable`, fields: {} });
      } catch (err) {
        return failureOutcome(id, Date.now() - start, err);
      }
    },
  };
}

export const cloudflareDnsProvider = makeDnsProvider(
  "cloudflare-dns",
  "Cloudflare DNS",
  resolveViaCloudflare,
  "https://developers.cloudflare.com/1.1.1.1/dns-over-https/"
);

export const googleDnsProvider = makeDnsProvider(
  "google-dns",
  "Google DNS",
  resolveViaGoogle,
  "https://developers.google.com/speed/public-dns/docs/doh"
);
