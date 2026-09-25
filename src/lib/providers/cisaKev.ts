import { requestJson, timed, successOutcome, failureOutcome } from "./base";
import { cisaKevResponseSchema } from "@/lib/validation/schemas";
import type { Provider, ProviderContext, ProviderOutcome } from "@/types/provider";
import type { ObservableType } from "@/types/observable";

const SUPPORTED: ObservableType[] = ["CVE"];
const FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

// The full feed is a few MB and changes infrequently; cache in-process for
// a short window rather than re-downloading it for every investigation.
let cache: { fetchedAt: number; data: Awaited<ReturnType<typeof fetchFeed>> } | null = null;
const CACHE_TTL_MS = 15 * 60 * 1000;

async function fetchFeed() {
  return requestJson(FEED_URL, cisaKevResponseSchema, { timeoutMs: 15000 });
}

async function getFeed() {
  if (cache && Date.now() - cache.fetchedAt < CACHE_TTL_MS) {
    return cache.data;
  }
  const data = await fetchFeed();
  cache = { fetchedAt: Date.now(), data };
  return data;
}

export const cisaKevProvider: Provider = {
  meta: {
    id: "cisa-kev",
    name: "CISA KEV",
    description: "CISA Known Exploited Vulnerabilities catalog — vulnerabilities confirmed to be actively exploited.",
    availability: "no-key",
    homepage: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    supports: SUPPORTED,
  },
  isConfigured: () => true,
  supports: (type) => SUPPORTED.includes(type),
  async investigate(ctx: ProviderContext): Promise<ProviderOutcome> {
    const start = Date.now();
    try {
      const { result, latencyMs } = await timed(() => getFeed());
      const entry = result.vulnerabilities.find((v) => v.cveID.toUpperCase() === ctx.observable.toUpperCase());

      if (!entry) {
        return successOutcome(this.meta.id, latencyMs, {
          summary: "Not listed in CISA KEV",
          fields: { listed: false },
        });
      }

      return successOutcome(
        this.meta.id,
        latencyMs,
        {
          summary: `Listed in CISA KEV since ${entry.dateAdded ?? "unknown date"}`,
          fields: {
            listed: true,
            vulnerabilityName: entry.vulnerabilityName,
            vendorProject: entry.vendorProject,
            product: entry.product,
            dateAdded: entry.dateAdded,
            dueDate: entry.dueDate,
            requiredAction: entry.requiredAction,
            knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
          },
          findings: [
            {
              severity: "CRITICAL",
              category: "vulnerability",
              title: "Known exploited vulnerability (CISA KEV)",
              description: `${ctx.observable} is listed in the CISA Known Exploited Vulnerabilities catalog, meaning CISA has confirmed active exploitation in the wild.`,
              evidence: `Added to the KEV catalog on ${entry.dateAdded ?? "an unspecified date"}. Required action: ${entry.requiredAction ?? "see CISA advisory"}.`,
            },
          ],
        },
        entry
      );
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
  async healthCheck(): Promise<ProviderOutcome> {
    const start = Date.now();
    try {
      const { latencyMs } = await timed(() => fetchFeed());
      return successOutcome(this.meta.id, latencyMs, { summary: "CISA KEV feed reachable", fields: {} });
    } catch (err) {
      return failureOutcome(this.meta.id, Date.now() - start, err);
    }
  },
};
