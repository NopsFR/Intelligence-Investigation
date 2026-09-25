import "server-only";
import { z } from "zod";
import { providerJson } from "@/lib/net/provider-fetch";

interface CachedFeed<T> {
  value?: T;
  fetchedAt?: number;
  inflight?: Promise<T>;
}

/** In-process feed cache with TTL and single-flight refresh. */
function feed<T>(ttlMs: number, load: () => Promise<T>) {
  const state: CachedFeed<T> = {};
  return {
    async get(): Promise<{ value: T; fetchedAt: number; fromCache: boolean }> {
      if (state.value !== undefined && state.fetchedAt && Date.now() - state.fetchedAt < ttlMs) {
        return { value: state.value, fetchedAt: state.fetchedAt, fromCache: true };
      }
      if (!state.inflight) {
        state.inflight = load()
          .then((value) => {
            state.value = value;
            state.fetchedAt = Date.now();
            return value;
          })
          .finally(() => {
            state.inflight = undefined;
          });
      }
      const value = await state.inflight;
      return { value, fetchedAt: state.fetchedAt ?? Date.now(), fromCache: false };
    },
    peek(): { value: T; fetchedAt: number } | null {
      return state.value !== undefined && state.fetchedAt ? { value: state.value, fetchedAt: state.fetchedAt } : null;
    },
  };
}

export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const kevSchema = z.object({
  catalogVersion: z.string().optional(),
  dateReleased: z.string().optional(),
  count: z.number().optional(),
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vendorProject: z.string().optional(),
      product: z.string().optional(),
      vulnerabilityName: z.string().optional(),
      dateAdded: z.string().optional(),
      shortDescription: z.string().optional(),
      requiredAction: z.string().optional(),
      dueDate: z.string().optional(),
      knownRansomwareCampaignUse: z.string().optional(),
      notes: z.string().optional(),
      cwes: z.array(z.string()).optional(),
    })
  ),
});
export type KevCatalog = z.infer<typeof kevSchema>;
export type KevEntry = KevCatalog["vulnerabilities"][number];

export const kevFeed = feed(60 * 60 * 1000, async () => {
  const { data } = await providerJson(KEV_URL, kevSchema, { timeoutMs: 15_000, maxBytes: 12 * 1024 * 1024 });
  return { ...data, index: new Map(data.vulnerabilities.map((v) => [v.cveID.toUpperCase(), v])) };
});

export const FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";

const feodoSchema = z.array(
  z.object({
    ip_address: z.string(),
    port: z.number().nullable().optional(),
    status: z.string().nullable().optional(),
    hostname: z.string().nullable().optional(),
    as_number: z.number().nullable().optional(),
    as_name: z.string().nullable().optional(),
    country: z.string().nullable().optional(),
    first_seen: z.string().nullable().optional(),
    last_online: z.string().nullable().optional(),
    malware: z.string().nullable().optional(),
  })
);
export type FeodoEntry = z.infer<typeof feodoSchema>[number];

export const feodoFeed = feed(15 * 60 * 1000, async () => {
  const { data } = await providerJson(FEODO_URL, feodoSchema, { timeoutMs: 10_000, maxBytes: 4 * 1024 * 1024 });
  const byIp = new Map<string, FeodoEntry[]>();
  for (const entry of data) {
    const list = byIp.get(entry.ip_address) ?? [];
    list.push(entry);
    byIp.set(entry.ip_address, list);
  }
  return { entries: data, byIp };
});
