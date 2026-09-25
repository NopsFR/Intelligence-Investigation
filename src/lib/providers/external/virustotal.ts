import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship, ObservableType, Severity } from "@/lib/core/types";
import { event, events, fact, facts, toIso, uniq } from "../helpers";
import type { ProviderDefinition } from "../types";

const stats = z
  .object({
    malicious: z.number().optional(),
    suspicious: z.number().optional(),
    harmless: z.number().optional(),
    undetected: z.number().optional(),
    timeout: z.number().optional(),
  })
  .passthrough();

const vtResponse = z.object({
  data: z.object({
    id: z.string(),
    type: z.string(),
    attributes: z
      .object({
        last_analysis_stats: stats.optional(),
        last_analysis_results: z.record(z.string(), z.object({ category: z.string().optional(), result: z.string().nullable().optional(), engine_name: z.string().optional() }).passthrough()).optional(),
        last_analysis_date: z.number().optional(),
        reputation: z.number().optional(),
        total_votes: z.object({ harmless: z.number().optional(), malicious: z.number().optional() }).optional(),
        tags: z.array(z.string()).optional(),
        categories: z.record(z.string(), z.string()).optional(),
        as_owner: z.string().optional(),
        asn: z.number().optional(),
        country: z.string().optional(),
        network: z.string().optional(),
        creation_date: z.number().optional(),
        registrar: z.string().optional(),
        type_description: z.string().optional(),
        meaningful_name: z.string().optional(),
        names: z.array(z.string()).optional(),
        size: z.number().optional(),
        first_submission_date: z.number().optional(),
        times_submitted: z.number().optional(),
        last_final_url: z.string().optional(),
        title: z.string().optional(),
        popular_threat_classification: z
          .object({
            suggested_threat_label: z.string().optional(),
            popular_threat_category: z.array(z.object({ value: z.string(), count: z.number() })).optional(),
            popular_threat_name: z.array(z.object({ value: z.string(), count: z.number() })).optional(),
          })
          .passthrough()
          .optional(),
        md5: z.string().optional(),
        sha1: z.string().optional(),
        sha256: z.string().optional(),
      })
      .passthrough(),
  }),
});

const notFound = z.object({ error: z.object({ code: z.string(), message: z.string().optional() }) });

function endpoint(observable: string, type: ObservableType): { url: string; gui: string } {
  const base = "https://www.virustotal.com/api/v3";
  switch (type) {
    case "IPV4":
    case "IPV6":
      return { url: `${base}/ip_addresses/${encodeURIComponent(observable)}`, gui: `https://www.virustotal.com/gui/ip-address/${observable}` };
    case "DOMAIN":
      return { url: `${base}/domains/${encodeURIComponent(observable)}`, gui: `https://www.virustotal.com/gui/domain/${observable}` };
    case "URL": {
      const id = Buffer.from(observable).toString("base64url");
      return { url: `${base}/urls/${id}`, gui: `https://www.virustotal.com/gui/url/${id}` };
    }
    default:
      return { url: `${base}/files/${observable}`, gui: `https://www.virustotal.com/gui/file/${observable}` };
  }
}

function severityFor(malicious: number): Severity {
  if (malicious >= 10) return "CRITICAL";
  if (malicious >= 4) return "HIGH";
  if (malicious >= 2) return "MEDIUM";
  return "LOW";
}

export const virusTotal: ProviderDefinition = {
  id: "virustotal",
  code: "VT",
  name: "VirusTotal",
  vendor: "Google",
  category: "reputation",
  kind: "external",
  description: "Aggregated verdicts from ~70 security vendors plus file, URL and infrastructure metadata.",
  homepage: "https://www.virustotal.com",
  docs: "https://docs.virustotal.com/reference/overview",
  auth: { type: "required", env: ["VIRUSTOTAL_API_KEY"], header: "x-apikey", signup: "https://www.virustotal.com/gui/join-us" },
  endpoint: "REST · JSON · www.virustotal.com/api/v3",
  limits: "Public API: 4 requests/minute, 500/day, non-commercial use only.",
  terms: "Public API may not be used in commercial products or services.",
  supports: ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"],
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 12_000,
  quotas: [
    { limit: 4, windowSeconds: 60, label: "free-tier limit of 4 requests per minute" },
    { limit: 500, windowSeconds: 86_400, label: "free-tier limit of 500 requests per day" },
  ],
  healthCheck: { observable: "8.8.8.8", type: "IPV4" },
  async run(ctx) {
    const { url, gui } = endpoint(ctx.observable, ctx.type);
    const response = await ctx.request(url, { headers: { "x-apikey": ctx.apiKey! }, acceptStatus: [404] });
    if (response.status === 404) {
      const body = ctx.parse(response, notFound);
      return { summary: "VirusTotal has no record of this observable", facts: [], empty: true, listed: false, raw: body };
    }
    const parsed = { data: ctx.parse(response, vtResponse) };
    const a = parsed.data.data.attributes;
    const s = a.last_analysis_stats ?? {};
    const malicious = s.malicious ?? 0;
    const suspicious = s.suspicious ?? 0;
    const engines = (s.malicious ?? 0) + (s.suspicious ?? 0) + (s.harmless ?? 0) + (s.undetected ?? 0);
    const flaggedBy = Object.entries(a.last_analysis_results ?? {})
      .filter(([, r]) => r.category === "malicious" || r.category === "suspicious")
      .map(([engine, r]) => `${engine}${r.result ? `: ${r.result}` : ""}`);
    const threatLabel = a.popular_threat_classification?.suggested_threat_label;
    const families = (a.popular_threat_classification?.popular_threat_name ?? []).map((n) => n.value);
    const categories = uniq(Object.values(a.categories ?? {}));
    const lastAnalysis = toIso(a.last_analysis_date);

    const findings: NormalizedFinding[] = [];
    if (malicious > 0 || suspicious >= 3) {
      findings.push({
        rule: "reputation.virustotal.detections",
        severity: malicious > 0 ? severityFor(malicious) : "LOW",
        category: "reputation",
        title: malicious > 0 ? `Flagged malicious by ${malicious} of ${engines} VirusTotal engines` : `Flagged suspicious by ${suspicious} VirusTotal engines`,
        description: `${malicious} engine(s) classified this ${ctx.type === "URL" ? "URL" : ctx.type.startsWith("IP") ? "address" : ctx.type === "DOMAIN" ? "domain" : "file"} as malicious and ${suspicious} as suspicious in the last analysis${lastAnalysis ? ` (${lastAnalysis.slice(0, 10)})` : ""}.`,
        rationale:
          "Individual engines produce false positives; confidence grows with the number of independent engines agreeing. Severity here scales with the malicious count (≥10 critical, ≥4 high, ≥2 medium).",
        evidence: flaggedBy.slice(0, 6).join(" · ") || "Engine names unavailable",
        evidenceData: { malicious, suspicious, harmless: s.harmless ?? 0, undetected: s.undetected ?? 0, engines, lastAnalysis: lastAnalysis ?? null, ...(threatLabel ? { threatLabel } : {}) },
        references: [{ label: "VirusTotal report", url: gui }],
      });
    }
    if ((a.reputation ?? 0) < -10) {
      findings.push({
        rule: "reputation.virustotal.community",
        severity: "LOW",
        category: "reputation",
        title: `Negative VirusTotal community reputation (${a.reputation})`,
        description: "VirusTotal community votes and comments net to a negative reputation score.",
        rationale: "Community reputation is crowd-sourced and noisy; treat it as supporting context only.",
        evidence: `Votes: ${a.total_votes?.malicious ?? 0} malicious / ${a.total_votes?.harmless ?? 0} harmless.`,
      });
    }

    const selfType = ctx.type === "URL" ? "url" : ctx.type === "DOMAIN" ? "domain" : ctx.type.startsWith("IP") ? "ip" : "hash";
    const relationships: NormalizedRelationship[] = [];
    for (const family of families.slice(0, 3)) {
      if (malicious > 0) relationships.push({ source: { type: selfType, value: ctx.observable }, target: { type: "malware", value: family }, type: "associated-with", evidence: `VirusTotal popular threat name (${threatLabel ?? family}).` });
    }
    if (a.asn && selfType === "ip") {
      relationships.push({ source: { type: "ip", value: ctx.observable }, target: { type: "asn", value: `AS${a.asn}`, label: a.as_owner }, type: "announced-by", evidence: "VirusTotal network metadata." });
    }

    return {
      summary: engines ? `${malicious}/${engines} engines malicious${threatLabel ? ` · ${threatLabel}` : ""}` : "No recent analysis",
      listed: malicious > 0,
      facts: facts(
        fact("detections", "Malicious detections", engines ? `${malicious} / ${engines}` : undefined, "mono", true),
        fact("suspicious", "Suspicious", suspicious, "number"),
        fact("threatLabel", "Threat label", threatLabel, "text", true),
        fact("families", "Popular threat names", families, "list"),
        fact("reputation", "Community reputation", a.reputation, "number"),
        fact("categories", "Categories", categories, "list"),
        fact("fileType", "File type", a.type_description, "text"),
        fact("fileName", "Meaningful name", a.meaningful_name, "mono"),
        fact("size", "Size", a.size, "bytes"),
        fact("asOwner", "AS owner", a.as_owner, "text"),
        fact("country", "Country", a.country, "text"),
        fact("network", "Network", a.network, "mono"),
        fact("registrar", "Registrar", a.registrar, "text"),
        fact("title", "Page title", a.title, "text"),
        fact("finalUrl", "Final URL", a.last_final_url, "url"),
        fact("lastAnalysis", "Last analysis", lastAnalysis, "datetime"),
        fact("tags", "Tags", a.tags ?? [], "list")
      ),
      data: { kind: "virustotal", stats: s, flaggedBy, threatLabel, families, gui },
      findings,
      relationships,
      links: [{ label: "Open in VirusTotal", url: gui }],
      timeline: events(
        event(a.first_submission_date, "First submitted to VirusTotal"),
        event(a.creation_date, "Domain creation date (VirusTotal WHOIS)"),
        event(a.last_analysis_date, "Last VirusTotal analysis", engines ? `${malicious}/${engines} malicious` : undefined)
      ),
      tags: a.tags ?? [],
      raw: { id: parsed.data.data.id, type: parsed.data.data.type, attributes: { ...a, last_analysis_results: undefined } },
    };
  },
};
