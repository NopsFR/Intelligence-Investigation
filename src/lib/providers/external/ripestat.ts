import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship } from "@/lib/core/types";
import { fact, facts, plural, uniq } from "../helpers";
import type { ProviderDefinition } from "../types";

const envelope = <T extends z.ZodTypeAny>(data: T) => z.object({ status: z.string(), data });

const networkInfo = envelope(z.object({ asns: z.array(z.string()), prefix: z.string().nullable().optional() }).passthrough());
const prefixOverview = envelope(
  z
    .object({
      announced: z.boolean().optional(),
      asns: z.array(z.object({ asn: z.number(), holder: z.string().nullable().optional() })).optional(),
      block: z.object({ resource: z.string().optional(), desc: z.string().optional(), name: z.string().optional() }).passthrough().optional(),
      resource: z.string().optional(),
    })
    .passthrough()
);
const asOverview = envelope(
  z
    .object({
      holder: z.string().nullable().optional(),
      announced: z.boolean().optional(),
      block: z.object({ resource: z.string().optional(), desc: z.string().optional() }).passthrough().optional(),
    })
    .passthrough()
);
const announcedPrefixes = envelope(
  z
    .object({
      prefixes: z.array(z.object({ prefix: z.string(), timelines: z.array(z.object({ starttime: z.string(), endtime: z.string() })).optional() })).optional(),
    })
    .passthrough()
);

const BASE = "https://stat.ripe.net/data";
const SOURCE = "sourceapp=nops-cyber-intelligence";

export const ripeStat: ProviderDefinition = {
  id: "ripestat",
  code: "RIS",
  name: "RIPEstat",
  vendor: "RIPE NCC",
  category: "infrastructure",
  kind: "external",
  description: "Live BGP routing data: origin AS, announced prefix, AS holder and announced address space.",
  homepage: "https://stat.ripe.net",
  docs: "https://stat.ripe.net/docs/data-api/",
  auth: { type: "none" },
  endpoint: "REST · JSON · stat.ripe.net/data",
  limits: "Public Data API; requests carry a sourceapp identifier as RIPE NCC requests.",
  terms: "RIPEstat Data API terms: https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions/",
  supports: ["IPV4", "IPV6", "ASN"],
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 12_000,
  healthCheck: { observable: "8.8.8.8", type: "IPV4" },
  async run(ctx) {
    if (ctx.type === "ASN") {
      const asn = ctx.observable.replace(/^AS/i, "");
      const [overview, prefixes] = await Promise.all([
        ctx.json(`${BASE}/as-overview/data.json?resource=AS${asn}&${SOURCE}`, asOverview),
        ctx.json(`${BASE}/announced-prefixes/data.json?resource=AS${asn}&${SOURCE}`, announcedPrefixes),
      ]);
      const holder = overview.data.data.holder ?? undefined;
      const list = (prefixes.data.data.prefixes ?? []).map((p) => p.prefix);
      const v4 = list.filter((p) => !p.includes(":"));
      const v6 = list.filter((p) => p.includes(":"));
      const findings: NormalizedFinding[] = [];
      if (overview.data.data.announced === false) {
        findings.push({
          rule: "routing.asn-not-announced",
          severity: "INFO",
          category: "infrastructure",
          title: "AS is not currently announcing any prefixes",
          description: `${ctx.observable} is registered but RIPEstat sees no active BGP announcements.`,
          rationale: "Dormant AS numbers are occasionally hijacked or re-activated for short-lived malicious routing.",
          evidence: "as-overview: announced = false",
        });
      }
      const relationships: NormalizedRelationship[] = list.slice(0, 15).map((prefix) => ({
        source: { type: "asn", value: ctx.observable, label: holder },
        target: { type: "prefix", value: prefix },
        type: "announces",
        evidence: "BGP announcement observed by RIPE RIS collectors.",
      }));
      return {
        summary: `${holder ?? ctx.observable} · ${plural(list.length, "prefix", "prefixes")} announced`,
        listed: true,
        facts: facts(
          fact("holder", "Holder", holder, "text", true),
          fact("announced", "Announced in BGP", overview.data.data.announced, "bool", true),
          fact("v4", "IPv4 prefixes", v4.length, "number", true),
          fact("v6", "IPv6 prefixes", v6.length, "number"),
          fact("block", "Registry block", overview.data.data.block?.desc, "text"),
          fact("sample", "Sample prefixes", list.slice(0, 8), "list")
        ),
        data: { kind: "ripestat-asn", holder, announced: overview.data.data.announced, prefixes: list.slice(0, 500), prefixCount: list.length },
        findings,
        relationships,
        links: [{ label: "RIPEstat", url: `https://stat.ripe.net/AS${asn}` }],
        raw: { overview: overview.data.data, prefixCount: list.length, prefixes: list.slice(0, 100) },
      };
    }

    const { data: info } = await ctx.json(`${BASE}/network-info/data.json?resource=${encodeURIComponent(ctx.observable)}&${SOURCE}`, networkInfo);
    const prefix = info.data.prefix ?? undefined;
    const asns = info.data.asns;
    if (!asns.length || !prefix) {
      return {
        summary: "Not announced in global BGP",
        facts: facts(fact("announced", "Announced in BGP", false, "bool", true)),
        findings: [
          {
            rule: "routing.ip-not-announced",
            severity: "INFO",
            category: "infrastructure",
            title: "Address is not announced in global BGP",
            description: "RIPEstat sees no route covering this address, so it is currently unreachable from the internet.",
            rationale: "Unrouted space should not originate traffic; seeing it in logs suggests spoofing or stale data.",
            evidence: "network-info: no origin AS",
          },
        ],
        data: { kind: "ripestat-ip", announced: false },
        raw: info.data,
      };
    }
    const { data: overview } = await ctx.json(`${BASE}/prefix-overview/data.json?resource=${encodeURIComponent(prefix)}&${SOURCE}`, prefixOverview);
    const holders = overview.data.asns ?? [];
    const multiOrigin = asns.length > 1;
    const findings: NormalizedFinding[] = multiOrigin
      ? [
          {
            rule: "routing.multiple-origins",
            severity: "INFO",
            category: "infrastructure",
            title: `Prefix announced by ${asns.length} origin ASes`,
            description: `${prefix} is originated by ${asns.map((a) => `AS${a}`).join(", ")}.`,
            rationale: "Multiple origins are normal for anycast and some multi-homed networks, but are also the signature of BGP hijacks.",
            evidence: `network-info asns: ${asns.join(", ")}`,
          },
        ]
      : [];
    const relationships: NormalizedRelationship[] = [
      ...asns.map((asn) => ({
        source: { type: "ip" as const, value: ctx.observable },
        target: { type: "asn" as const, value: `AS${asn}`, label: holders.find((h) => String(h.asn) === asn)?.holder ?? undefined },
        type: "announced-by",
        evidence: `Origin AS of ${prefix} (RIPE RIS).`,
      })),
      { source: { type: "ip", value: ctx.observable }, target: { type: "prefix", value: prefix }, type: "announced-in", evidence: "Most specific announced prefix (RIPE RIS)." },
    ];
    return {
      summary: `AS${asns.join(", AS")} ${holders[0]?.holder ?? ""} · ${prefix}`.trim(),
      listed: true,
      facts: facts(
        fact("asn", "Origin AS", asns.map((a) => `AS${a}`), "list", true),
        fact("holder", "AS holder", uniq(holders.map((h) => h.holder)), "list", true),
        fact("prefix", "Announced prefix", prefix, "mono", true),
        fact("announced", "Announced in BGP", overview.data.announced, "bool"),
        fact("block", "Registry block", overview.data.block?.desc, "text")
      ),
      data: { kind: "ripestat-ip", announced: true, asns, prefix, holders },
      findings,
      relationships,
      links: [{ label: "RIPEstat", url: `https://stat.ripe.net/${ctx.observable}` }],
      raw: { networkInfo: info.data, prefixOverview: overview.data },
    };
  },
};
