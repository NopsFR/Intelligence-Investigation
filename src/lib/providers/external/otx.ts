import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship, NodeType, ObservableType, Severity } from "@/lib/core/types";
import { event, events, fact, facts, plural, toIso, uniq } from "../helpers";
import type { ProviderDefinition } from "../types";

const labelled = z.union([
  z.string(),
  z.object({ id: z.string().optional(), display_name: z.string().optional(), name: z.string().optional() }).passthrough(),
]);

const pulse = z
  .object({
    id: z.string(),
    name: z.string(),
    created: z.string().optional(),
    modified: z.string().optional(),
    tags: z.array(z.string()).optional(),
    references: z.array(z.string()).optional(),
    adversary: z.string().nullable().optional(),
    malware_families: z.array(labelled).optional(),
    attack_ids: z.array(labelled).optional(),
    industries: z.array(z.string()).optional(),
    TLP: z.string().optional(),
    author: z.object({ username: z.string().optional() }).passthrough().optional(),
  })
  .passthrough();

const otxResponse = z
  .object({
    indicator: z.string().optional(),
    type: z.string().optional(),
    reputation: z.number().nullable().optional(),
    validation: z.array(z.object({ source: z.string().optional(), message: z.string().optional(), name: z.string().optional() }).passthrough()).optional(),
    pulse_info: z
      .object({
        count: z.number(),
        pulses: z.array(pulse),
        related: z
          .object({
            alienvault: z.object({ adversary: z.array(z.string()).optional(), malware_families: z.array(z.string()).optional() }).passthrough().optional(),
            other: z.object({ adversary: z.array(z.string()).optional(), malware_families: z.array(z.string()).optional() }).passthrough().optional(),
          })
          .passthrough()
          .optional(),
      })
      .passthrough()
      .optional(),
    asn: z.string().nullable().optional(),
    country_name: z.string().nullable().optional(),
    base_indicator: z.object({ id: z.number().optional() }).passthrough().optional(),
  })
  .passthrough();

function section(type: ObservableType, observable: string): { path: string; gui: string } {
  const enc = encodeURIComponent(observable);
  switch (type) {
    case "IPV4":
      return { path: `IPv4/${enc}`, gui: `https://otx.alienvault.com/indicator/ip/${observable}` };
    case "IPV6":
      return { path: `IPv6/${enc}`, gui: `https://otx.alienvault.com/indicator/ip/${observable}` };
    case "DOMAIN":
      return { path: `hostname/${enc}`, gui: `https://otx.alienvault.com/indicator/hostname/${observable}` };
    case "URL":
      return { path: `url/${enc}`, gui: `https://otx.alienvault.com/indicator/url/${enc}` };
    case "CVE":
      return { path: `cve/${enc}`, gui: `https://otx.alienvault.com/indicator/cve/${observable}` };
    default:
      return { path: `file/${enc}`, gui: `https://otx.alienvault.com/indicator/file/${observable}` };
  }
}

const labelOf = (v: z.infer<typeof labelled>) => (typeof v === "string" ? v : v.display_name ?? v.name ?? v.id ?? "");
const idOf = (v: z.infer<typeof labelled>) => (typeof v === "string" ? v : v.id ?? v.display_name ?? "");

function selfNodeType(type: ObservableType): NodeType {
  if (type === "URL") return "url";
  if (type === "DOMAIN") return "domain";
  if (type === "CVE") return "cve";
  if (type.startsWith("IP")) return "ip";
  return "hash";
}

export const otx: ProviderDefinition = {
  id: "otx",
  code: "OTX",
  name: "AlienVault OTX",
  vendor: "LevelBlue",
  category: "threat-intel",
  kind: "external",
  description: "Open Threat Exchange community pulses: crowd-sourced threat reports referencing indicators.",
  homepage: "https://otx.alienvault.com",
  docs: "https://otx.alienvault.com/api",
  auth: { type: "optional", env: ["OTX_API_KEY"], header: "X-OTX-API-KEY", signup: "https://otx.alienvault.com/", benefit: "Higher rate limits and access to private/subscribed pulses." },
  endpoint: "REST · JSON · otx.alienvault.com/api/v1/indicators",
  limits: "Anonymous access is rate limited; responses for popular indicators can be large and slow.",
  terms: "Community-submitted content; not authoritative.",
  supports: ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256", "CVE"],
  quick: ["IPV4", "IPV6", "MD5", "SHA1", "SHA256"],
  cacheTtlSeconds: 2 * 60 * 60,
  timeoutMs: 15_000,
  healthCheck: { observable: "8.8.8.8", type: "IPV4" },
  async run(ctx) {
    const { path, gui } = section(ctx.type, ctx.observable);
    const { data } = await ctx.json(`https://otx.alienvault.com/api/v1/indicators/${path}/general`, otxResponse, {
      headers: ctx.apiKey ? { "X-OTX-API-KEY": ctx.apiKey } : {},
      maxBytes: 10 * 1024 * 1024,
      retries: 0,
    });

    const pulses = data.pulse_info?.pulses ?? [];
    const count = data.pulse_info?.count ?? pulses.length;
    const validation = data.validation ?? [];
    const allowlisted = validation.filter((v) => /whitelist|false_positive|false positive|akamai|majestic|alexa/i.test(`${v.source} ${v.name}`));

    const families = uniq([
      ...pulses.flatMap((p) => (p.malware_families ?? []).map(labelOf)),
      ...(data.pulse_info?.related?.alienvault?.malware_families ?? []),
      ...(data.pulse_info?.related?.other?.malware_families ?? []),
    ]).filter((f) => f.length < 60);
    const adversaries = uniq([...pulses.map((p) => p.adversary), ...(data.pulse_info?.related?.other?.adversary ?? [])]);
    const techniqueCounts = new Map<string, { label: string; pulses: number }>();
    for (const p of pulses) {
      for (const a of p.attack_ids ?? []) {
        const id = idOf(a).match(/T\d{4}(?:\.\d{3})?/)?.[0];
        if (!id) continue;
        const entry = techniqueCounts.get(id) ?? { label: labelOf(a), pulses: 0 };
        entry.pulses++;
        techniqueCounts.set(id, entry);
      }
    }
    const created = pulses.map((p) => toIso(p.created)).filter(Boolean).sort();
    const modified = pulses.map((p) => toIso(p.modified)).filter(Boolean).sort();

    if (count === 0) {
      return {
        summary: allowlisted.length ? `No pulses · allowlisted (${allowlisted.map((v) => v.name ?? v.source).join(", ")})` : "Not referenced in any OTX pulse",
        facts: facts(fact("validation", "OTX validation", allowlisted.map((v) => v.message ?? v.name ?? ""), "list")),
        empty: true,
        listed: false,
        data: { kind: "otx", pulses: [], validation, gui },
        raw: { ...data, pulse_info: undefined },
      };
    }

    const findings: NormalizedFinding[] = [];
    const severity: Severity = allowlisted.length ? "INFO" : count >= 10 ? "MEDIUM" : "LOW";
    findings.push({
      rule: allowlisted.length ? "intel.otx.pulses-allowlisted" : "intel.otx.pulses",
      severity,
      category: "threat-intelligence",
      title: `Referenced in ${plural(count, "OTX community pulse")}`,
      description: `${plural(count, "pulse")} on AlienVault OTX include this indicator${families.length ? `, mentioning ${families.slice(0, 4).join(", ")}` : ""}${adversaries.length ? ` and adversary ${adversaries.slice(0, 2).join(", ")}` : ""}.`,
      rationale: allowlisted.length
        ? `OTX itself marks this indicator as ${allowlisted.map((v) => v.name ?? v.source).join(", ")}, so pulse references are likely incidental (popular infrastructure appears in many reports).`
        : "OTX pulses are community submissions of varying quality. Many pulses indicate the indicator appears in threat reporting; read the pulses before treating it as malicious.",
      evidence: pulses.slice(0, 3).map((p) => `“${p.name}”`).join(" · "),
      evidenceData: { pulses: count, families: families.slice(0, 10), adversaries: adversaries.slice(0, 5), techniques: [...techniqueCounts.keys()].slice(0, 12), allowlisted: allowlisted.map((v) => v.name ?? v.source ?? "") },
      confidence: "Community intelligence",
      references: [{ label: "OTX indicator", url: gui }, ...pulses.slice(0, 3).map((p) => ({ label: p.name.slice(0, 80), url: `https://otx.alienvault.com/pulse/${p.id}` }))],
    });

    const self = selfNodeType(ctx.type);
    const relationships: NormalizedRelationship[] = [
      ...families.slice(0, 6).map((family) => ({
        source: { type: self, value: ctx.observable },
        target: { type: "malware" as const, value: family },
        type: "mentioned-with",
        evidence: `Named alongside this indicator in OTX pulses (community).`,
      })),
      ...[...techniqueCounts.entries()].slice(0, 12).map(([id, t]) => ({
        source: { type: self, value: ctx.observable },
        target: { type: "technique" as const, value: id, label: t.label.replace(/^T[\d.]+\s*-\s*/, "") },
        type: "mentioned-with",
        evidence: `${plural(t.pulses, "OTX pulse")} referencing this indicator tag ${id}.`,
      })),
    ];

    return {
      summary: `${plural(count, "pulse")}${families.length ? ` · ${families.slice(0, 3).join(", ")}` : ""}`,
      listed: !allowlisted.length,
      facts: facts(
        fact("pulses", "Pulses", count, "number", true),
        fact("families", "Malware families", families.slice(0, 10), "list", true),
        fact("adversaries", "Adversaries", adversaries.slice(0, 5), "list"),
        fact("techniques", "ATT&CK techniques", [...techniqueCounts.keys()].slice(0, 15), "list"),
        fact("validation", "OTX validation", allowlisted.map((v) => v.message ?? v.name ?? ""), "list"),
        fact("asn", "ASN", data.asn, "text"),
        fact("country", "Country", data.country_name, "text"),
        fact("firstPulse", "Earliest pulse", created[0], "date"),
        fact("latestPulse", "Latest update", modified.at(-1), "date")
      ),
      data: {
        kind: "otx",
        gui,
        validation,
        pulses: pulses.slice(0, 25).map((p) => ({
          id: p.id,
          name: p.name,
          created: p.created,
          modified: p.modified,
          tags: (p.tags ?? []).slice(0, 8),
          adversary: p.adversary,
          families: (p.malware_families ?? []).map(labelOf),
          techniques: (p.attack_ids ?? []).map(idOf),
          tlp: p.TLP,
          author: p.author?.username,
          references: (p.references ?? []).slice(0, 5),
        })),
      },
      findings,
      relationships,
      links: [{ label: "Open in OTX", url: gui }],
      timeline: events(event(created[0], "First OTX pulse referencing this indicator"), event(modified.at(-1), "Most recent OTX pulse update")),
      tags: uniq(pulses.flatMap((p) => p.tags ?? [])).slice(0, 20),
      raw: { ...data, pulse_info: { count, pulses: pulses.slice(0, 10) } },
    };
  },
};
