import "server-only";
import { z } from "zod";
import { providerJson, providerRequest } from "@/lib/net/provider-fetch";

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

// abuse.ch has required a free Auth-Key for its APIs since 2025; without it these
// export feeds still respond 200 but silently redact the actual indicator value
// (ioc / id / url) from every row, which otherwise looks like "0 usable entries".
function abusechHeaders(): Record<string, string> {
  const key = process.env.ABUSECH_AUTH_KEY?.trim();
  return key ? { "Auth-Key": key } : {};
}

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
  const { data } = await providerJson(FEODO_URL, feodoSchema, { timeoutMs: 10_000, maxBytes: 4 * 1024 * 1024, headers: abusechHeaders() });
  const byIp = new Map<string, FeodoEntry[]>();
  for (const entry of data) {
    const list = byIp.get(entry.ip_address) ?? [];
    list.push(entry);
    byIp.set(entry.ip_address, list);
  }
  return { entries: data, byIp };
});

// ---------------------------------------------------------------- abuse.ch recent exports (threat feed)

// Accepts a string too — some abuse.ch export rows carry tags as a
// comma-separated string rather than a JSON array — and normalises to string[].
const looseTags = z
  .union([z.array(z.string()), z.string()])
  .nullable()
  .optional()
  .transform((v) => (Array.isArray(v) ? v : typeof v === "string" ? v.split(",").map((t) => t.trim()).filter(Boolean) : []));

const threatFoxSchema = z.record(
  z.string(),
  z.array(
    z.object({
      ioc: z.string().nullable().optional(),
      ioc_type: z.string().nullable().optional(),
      threat_type: z.string().nullable().optional(),
      malware: z.string().nullable().optional(),
      malware_printable: z.string().nullable().optional(),
      confidence_level: z.number().nullable().optional(),
      first_seen_utc: z.string().nullable().optional(),
      reference: z.string().nullable().optional(),
      tags: looseTags,
    })
  )
);
export type ThreatFoxEntry = z.infer<typeof threatFoxSchema>[string][number];

export const THREATFOX_RECENT_URL = "https://threatfox.abuse.ch/export/json/recent/";

export const threatFoxRecentFeed = feed(15 * 60 * 1000, async () => {
  const { data } = await providerJson(THREATFOX_RECENT_URL, threatFoxSchema, { timeoutMs: 20_000, maxBytes: 6 * 1024 * 1024, headers: abusechHeaders() });
  const raw = Object.values(data).flat();
  // A small number of ThreatFox export rows omit the ioc/ioc_type fields; those carry
  // no usable indicator, so they are dropped rather than surfaced as blank rows.
  const entries = raw.filter((e): e is ThreatFoxEntry & { ioc: string; ioc_type: string } => Boolean(e.ioc && e.ioc_type));
  // Surface a diagnostic sample rather than a silent "0 results" if the upstream shape
  // ever drifts again and every raw row gets filtered out.
  const diagnostics = entries.length === 0 && raw.length > 0 ? { rawCount: raw.length, sample: JSON.stringify(raw[0]).slice(0, 300) } : undefined;
  return { entries, count: entries.length, ...(diagnostics ? { diagnostics } : {}) };
});

const urlhausEntry = z.object({
  id: z.string().nullable().optional(),
  url: z.string().nullable().optional(),
  url_status: z.string().nullable().optional(),
  threat: z.string().nullable().optional(),
  host: z.string().nullable().optional(),
  date_added: z.string().nullable().optional(),
  reporter: z.string().nullable().optional(),
  tags: looseTags,
});
// The live export has been observed as both a bare array and an ID-keyed
// object (the same shape ThreatFox's recent export uses) — accept either.
const urlhausSchema = z.union([z.array(urlhausEntry), z.record(z.string(), z.union([urlhausEntry, z.array(urlhausEntry)]))]);
export type UrlhausEntry = z.infer<typeof urlhausEntry>;

export const URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/json_recent/";

export const urlhausRecentFeed = feed(15 * 60 * 1000, async () => {
  const { data } = await providerJson(URLHAUS_RECENT_URL, urlhausSchema, { timeoutMs: 20_000, maxBytes: 8 * 1024 * 1024, headers: abusechHeaders() });
  const raw = Array.isArray(data) ? data : Object.values(data).flat();
  const entries = raw.filter((e): e is UrlhausEntry & { id: string; url: string } => Boolean(e.id && e.url));
  const diagnostics = entries.length === 0 && raw.length > 0 ? { rawCount: raw.length, sample: JSON.stringify(raw[0]).slice(0, 300) } : undefined;
  return { entries, count: entries.length, ...(diagnostics ? { diagnostics } : {}) };
});

export interface BazaarEntry {
  firstSeen: string;
  sha256: string;
  md5: string;
  sha1: string;
  reporter: string;
  fileName: string;
  fileType: string;
  mimeType: string;
  signature: string;
  tags: string[];
}

export const BAZAAR_RECENT_URL = "https://bazaar.abuse.ch/export/csv/recent/";

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cell = "";
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') q = false;
      else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") {
      out.push(cell);
      cell = "";
    } else cell += c;
  }
  out.push(cell);
  return out;
}

export const bazaarRecentFeed = feed(15 * 60 * 1000, async () => {
  const response = await providerRequest(BAZAAR_RECENT_URL, { timeoutMs: 20_000, maxBytes: 2 * 1024 * 1024, headers: abusechHeaders() });
  const text = response.text;
  const entries: BazaarEntry[] = [];
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const cols = parseCsvLine(line);
    if (cols.length < 9) continue;
    const [firstSeen, sha256, md5, sha1, reporter, fileName, fileType, mimeType, signature, tagsRaw] = cols;
    entries.push({ firstSeen, sha256, md5, sha1, reporter, fileName, fileType, mimeType, signature, tags: (tagsRaw ?? "").split(",").map((t) => t.trim()).filter(Boolean) });
  }
  return { entries: entries.slice(0, 1000), count: entries.length };
});

// ---------------------------------------------------------------- NVD recent CVEs + EPSS ranking

const nvdRecentSchema = z.object({
  totalResults: z.number().optional(),
  vulnerabilities: z.array(
    z.object({
      cve: z.object({
        id: z.string(),
        published: z.string().optional(),
        lastModified: z.string().optional(),
        vulnStatus: z.string().optional(),
        descriptions: z.array(z.object({ lang: z.string(), value: z.string() })).optional(),
        metrics: z
          .object({
            cvssMetricV40: z.array(z.object({ cvssData: z.object({ baseScore: z.number(), baseSeverity: z.string().optional(), vectorString: z.string().optional() }) })).optional(),
            cvssMetricV31: z.array(z.object({ cvssData: z.object({ baseScore: z.number(), baseSeverity: z.string().optional(), vectorString: z.string().optional() }) })).optional(),
            cvssMetricV30: z.array(z.object({ cvssData: z.object({ baseScore: z.number(), baseSeverity: z.string().optional(), vectorString: z.string().optional() }) })).optional(),
            cvssMetricV2: z.array(z.object({ cvssData: z.object({ baseScore: z.number(), vectorString: z.string().optional() }), baseSeverity: z.string().optional() })).optional(),
          })
          .optional(),
        weaknesses: z.array(z.object({ description: z.array(z.object({ value: z.string() })) })).optional(),
      }),
    })
  ),
});

export interface RecentCve {
  id: string;
  published?: string;
  lastModified?: string;
  status?: string;
  description?: string;
  cvss?: { score: number; severity?: string; vector?: string; version: string };
  cwes: string[];
}

export const NVD_RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export const nvdRecentFeed = feed(30 * 60 * 1000, async () => {
  const end = new Date();
  const start = new Date(end.getTime() - 8 * 86400_000);
  const url = `${NVD_RECENT_URL}?pubStartDate=${start.toISOString().slice(0, 19)}.000&pubEndDate=${end.toISOString().slice(0, 19)}.000&resultsPerPage=200`;
  const { data } = await providerJson(url, nvdRecentSchema, { timeoutMs: 20_000, maxBytes: 6 * 1024 * 1024, headers: process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {} });
  const entries: RecentCve[] = data.vulnerabilities.map(({ cve }) => {
    const m = cve.metrics ?? {};
    const all = [...(m.cvssMetricV40 ?? []).map((x) => ({ ...x.cvssData, version: "4.0" })), ...(m.cvssMetricV31 ?? []).map((x) => ({ ...x.cvssData, version: "3.1" })), ...(m.cvssMetricV30 ?? []).map((x) => ({ ...x.cvssData, version: "3.0" })), ...(m.cvssMetricV2 ?? []).map((x) => ({ baseScore: x.cvssData.baseScore, baseSeverity: x.baseSeverity, vectorString: x.cvssData.vectorString, version: "2.0" }))];
    const primary = all[0];
    return {
      id: cve.id,
      published: cve.published,
      lastModified: cve.lastModified,
      status: cve.vulnStatus,
      description: cve.descriptions?.find((d) => d.lang === "en")?.value,
      cvss: primary ? { score: primary.baseScore, severity: primary.baseSeverity, vector: primary.vectorString, version: primary.version } : undefined,
      cwes: [...new Set((cve.weaknesses ?? []).flatMap((w) => w.description.map((d) => d.value)))].filter((c) => c.startsWith("CWE-")),
    };
  });
  return { entries: entries.sort((a, b) => (b.published ?? "").localeCompare(a.published ?? "")), totalResults: data.totalResults ?? entries.length };
});

const epssSchema = z.object({ data: z.array(z.object({ cve: z.string(), epss: z.string(), percentile: z.string() })) });
export interface EpssEntry {
  cve: string;
  epss: number;
  percentile: number;
}

export const EPSS_TOP_URL = "https://api.first.org/data/v1/epss";

export const epssTopFeed = feed(60 * 60 * 1000, async () => {
  const { data } = await providerJson(`${EPSS_TOP_URL}?order=!epss&limit=100`, epssSchema, { timeoutMs: 15_000, maxBytes: 1024 * 1024 });
  const entries: EpssEntry[] = data.data.map((d) => ({ cve: d.cve, epss: Number(d.epss), percentile: Number(d.percentile) }));
  return { entries, index: new Map(entries.map((e) => [e.cve.toUpperCase(), e])) };
});

export async function epssScores(cveIds: string[]): Promise<Map<string, EpssEntry>> {
  if (!cveIds.length) return new Map();
  const { data } = await providerJson(`${EPSS_TOP_URL}?cve=${cveIds.map(encodeURIComponent).join(",")}`, epssSchema, { timeoutMs: 15_000, maxBytes: 512 * 1024 });
  return new Map(data.data.map((d) => [d.cve.toUpperCase(), { cve: d.cve, epss: Number(d.epss), percentile: Number(d.percentile) }]));
}

// ---------------------------------------------------------------- HIBP breach catalogue (keyless)

const hibpBreachSchema = z.object({
  Name: z.string(),
  Title: z.string(),
  Domain: z.string().optional(),
  BreachDate: z.string().optional(),
  AddedDate: z.string().optional(),
  ModifiedDate: z.string().optional(),
  PwnCount: z.number().optional(),
  Description: z.string().optional(),
  DataClasses: z.array(z.string()).optional(),
  IsVerified: z.boolean().optional(),
  IsFabricated: z.boolean().optional(),
  IsSensitive: z.boolean().optional(),
  IsRetired: z.boolean().optional(),
  IsSpamList: z.boolean().optional(),
  IsMalware: z.boolean().optional(),
  LogoPath: z.string().optional(),
});
export type HibpBreach = z.infer<typeof hibpBreachSchema>;

export const HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches";

export const hibpBreachCatalogueFeed = feed(6 * 60 * 60 * 1000, async () => {
  const { data } = await providerJson(HIBP_BREACHES_URL, z.array(hibpBreachSchema), { timeoutMs: 15_000, maxBytes: 4 * 1024 * 1024, headers: { "user-agent": "NOPS-Cyber-Intelligence" } });
  const byDomain = new Map<string, HibpBreach[]>();
  for (const b of data) if (b.Domain) {
    const key = b.Domain.toLowerCase();
    const list = byDomain.get(key) ?? [];
    list.push(b);
    byDomain.set(key, list);
  }
  return { entries: data, byDomain };
});

// ---------------------------------------------------------------- IEEE OUI (MAC vendor) registry

export const OUI_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv";

export const ouiFeed = feed(24 * 60 * 60 * 1000, async () => {
  const response = await providerRequest(OUI_CSV_URL, { timeoutMs: 20_000, maxBytes: 6 * 1024 * 1024 });
  const byPrefix = new Map<string, string>();
  for (const line of response.text.split("\n")) {
    // Registry,Assignment,Organization Name,Organization Address
    const m = /^MA-L,([0-9A-F]{6}),"?([^",]+)"?/i.exec(line);
    if (m) byPrefix.set(m[1].toUpperCase(), m[2].trim());
  }
  return { byPrefix, count: byPrefix.size };
});

export async function lookupOui(mac: string): Promise<{ prefix: string; vendor: string } | null> {
  const hex = mac.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  if (hex.length < 6) return null;
  const prefix = hex.slice(0, 6);
  const { value } = await ouiFeed.get();
  const vendor = value.byPrefix.get(prefix);
  return vendor ? { prefix, vendor } : null;
}
