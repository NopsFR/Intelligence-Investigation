import "server-only";
import { z } from "zod";
import type { NormalizedRelationship } from "@/lib/core/types";
import { fact, facts, toIso, uniq } from "../helpers";
import type { ProviderDefinition } from "../types";
// ---------------------------------------------------------------- Mnemonic Argus passive DNS (keyless)

const mnemonicSchema = z.object({
  data: z
    .array(
      z.object({
        query: z.string(),
        answer: z.string(),
        rrtype: z.string(),
        rrclass: z.string().optional(),
        ttl: z.number().optional(),
        firstSeenTimestamp: z.number().optional(),
        lastSeenTimestamp: z.number().optional(),
        times: z.number().optional(),
        tags: z.array(z.string()).optional(),
      })
    )
    .default([]),
  count: z.number().optional(),
  size: z.number().optional(),
});

const REVERSE_RRTYPES = new Set(["a", "aaaa"]);

export const mnemonicPassiveDns: ProviderDefinition = {
  id: "mnemonic-pdns",
  code: "PDNS",
  name: "Mnemonic Passive DNS",
  vendor: "mnemonic",
  category: "dns",
  kind: "external",
  description: "Historical DNS resolutions observed by mnemonic's sensor network: what a domain has resolved to, and what has resolved to an IP address, over time.",
  homepage: "https://www.mnemonic.no",
  docs: "https://docs.mnemonic.no/display/public/API/Passive+DNS+Overview",
  auth: { type: "none" },
  endpoint: "REST · JSON · api.mnemonic.no/pdns/v3",
  limits: "Public keyless access; reasonable use.",
  supports: ["DOMAIN", "IPV4", "IPV6"],
  cacheTtlSeconds: 60 * 60,
  timeoutMs: 12_000,
  quotas: [{ limit: 30, windowSeconds: 60, label: "30 requests per minute" }],
  healthCheck: { observable: "google.com", type: "DOMAIN" },
  skip: ({ type }) => (type === "IPV6" ? "IPv6 reverse lookups are not indexed by this source" : null),
  async run(ctx) {
    const forward = ctx.type === "DOMAIN";
    const url = `https://api.mnemonic.no/pdns/v3/${forward ? "search" : encodeURIComponent(ctx.observable)}${forward ? `?query=${encodeURIComponent(ctx.observable)}&limit=200` : "?limit=200"}`;
    const { data } = await ctx.json(url, mnemonicSchema);
    const records = forward ? data.data.filter((r) => r.query.toLowerCase() === ctx.observable.toLowerCase()) : data.data.filter((r) => REVERSE_RRTYPES.has(r.rrtype.toLowerCase()));
    if (!records.length) return { summary: "No passive-DNS resolutions on record", facts: [], empty: true, data: { kind: "passive-dns", records: [] } };

    records.sort((a, b) => (b.lastSeenTimestamp ?? 0) - (a.lastSeenTimestamp ?? 0));
    const byType = new Map<string, typeof records>();
    for (const r of records) {
      const list = byType.get(r.rrtype.toUpperCase()) ?? [];
      list.push(r);
      byType.set(r.rrtype.toUpperCase(), list);
    }
    const relationships: NormalizedRelationship[] = [];
    if (forward) {
      for (const r of records.slice(0, 60)) {
        if (r.rrtype.toLowerCase() === "a" || r.rrtype.toLowerCase() === "aaaa") relationships.push({ source: { type: "domain", value: ctx.observable }, target: { type: "ip", value: r.answer }, type: "resolved-to", evidence: `Passive DNS: ${r.rrtype.toUpperCase()} seen ${r.times ?? 1} time(s), last ${toIso(r.lastSeenTimestamp) ?? "?"}.` });
        else if (r.rrtype.toLowerCase() === "cname") relationships.push({ source: { type: "domain", value: ctx.observable }, target: { type: "domain", value: r.answer.replace(/\.$/, "") }, type: "aliases", evidence: `Passive DNS CNAME, last seen ${toIso(r.lastSeenTimestamp) ?? "?"}.` });
      }
    } else {
      for (const r of uniq(records.map((r) => r.query.replace(/\.$/, ""))).slice(0, 60)) relationships.push({ source: { type: "ip", value: ctx.observable }, target: { type: "domain", value: r }, type: "resolved-from", evidence: "Passive DNS: this domain has resolved to this address." });
    }

    return {
      summary: forward ? `${records.length} passive-DNS record${records.length === 1 ? "" : "s"} across ${byType.size} type${byType.size === 1 ? "" : "s"}` : `${uniq(records.map((r) => r.query)).length} domain(s) seen resolving here`,
      facts: facts(
        fact("records", "Records", records.length, "number", true),
        fact("types", "Record types", [...byType.keys()], "list"),
        fact("firstSeen", "Earliest observation", toIso(Math.min(...records.map((r) => r.firstSeenTimestamp ?? Infinity))), "date"),
        fact("lastSeen", "Latest observation", toIso(Math.max(...records.map((r) => r.lastSeenTimestamp ?? 0))), "date")
      ),
      data: { kind: "passive-dns", records: records.slice(0, 200).map((r) => ({ query: r.query, answer: r.answer, rrtype: r.rrtype.toUpperCase(), firstSeen: toIso(r.firstSeenTimestamp), lastSeen: toIso(r.lastSeenTimestamp), times: r.times })) },
      relationships,
      links: [{ label: "mnemonic passive DNS", url: `https://www.mnemonic.no` }],
    };
  },
};

// ---------------------------------------------------------------- urlscan.io search (keyless)

const urlscanSchema = z.object({
  total: z.number().optional(),
  results: z
    .array(
      z.object({
        task: z.object({ time: z.string().optional(), url: z.string().optional(), method: z.string().optional() }).optional(),
        page: z.object({ url: z.string().optional(), domain: z.string().optional(), ip: z.string().optional(), country: z.string().optional(), server: z.string().optional(), title: z.string().optional(), asn: z.string().optional(), asnname: z.string().optional() }).optional(),
        stats: z.object({ malicious: z.number().optional() }).optional(),
        verdicts: z.object({ overall: z.object({ malicious: z.boolean().optional(), score: z.number().optional() }).optional() }).optional(),
        _id: z.string().optional(),
      })
    )
    .default([]),
});

export const urlscanSearch: ProviderDefinition = {
  id: "urlscan-search",
  code: "URLSCN",
  name: "urlscan.io Search",
  vendor: "urlscan.io",
  category: "reputation",
  kind: "external",
  description: "Historical page scans mentioning this domain or URL: what urlscan.io's crawler saw, when, and from where.",
  homepage: "https://urlscan.io",
  docs: "https://urlscan.io/docs/search/",
  auth: { type: "none" },
  endpoint: "REST · JSON · urlscan.io/api/v1/search",
  limits: "Public search API; reasonable use.",
  supports: ["DOMAIN", "URL"],
  cacheTtlSeconds: 30 * 60,
  timeoutMs: 12_000,
  quotas: [{ limit: 60, windowSeconds: 60, label: "60 requests per minute" }],
  healthCheck: { observable: "google.com", type: "DOMAIN" },
  async run(ctx) {
    const query = ctx.type === "URL" ? `page.url:"${ctx.observable}"` : `domain:"${ctx.observable}"`;
    const { data } = await ctx.json(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=40`, urlscanSchema);
    if (!data.results.length) return { summary: "No urlscan.io scans found", facts: [], empty: true, data: { kind: "urlscan-search", results: [] } };
    const malicious = data.results.filter((r) => r.verdicts?.overall?.malicious).length;
    const countries = uniq(data.results.map((r) => r.page?.country)).filter((c): c is string => !!c);
    const ips = uniq(data.results.map((r) => r.page?.ip)).filter((c): c is string => !!c);
    return {
      summary: `${data.total ?? data.results.length} scan${(data.total ?? data.results.length) === 1 ? "" : "s"}${malicious ? `, ${malicious} flagged malicious` : ""}`,
      facts: facts(fact("total", "Total scans", data.total ?? data.results.length, "number", true), fact("malicious", "Flagged malicious", malicious, "number"), fact("countries", "Hosting countries seen", countries, "list"), fact("ips", "IPs seen", ips.slice(0, 10), "list")),
      data: { kind: "urlscan-search", results: data.results.slice(0, 40).map((r) => ({ id: r._id, time: r.task?.time, url: r.page?.url, domain: r.page?.domain, ip: r.page?.ip, country: r.page?.country, server: r.page?.server, title: r.page?.title, malicious: !!r.verdicts?.overall?.malicious, score: r.verdicts?.overall?.score })) },
      links: data.results[0]?._id ? [{ label: "View on urlscan.io", url: `https://urlscan.io/search/#${encodeURIComponent(query)}` }] : [],
    };
  },
};
