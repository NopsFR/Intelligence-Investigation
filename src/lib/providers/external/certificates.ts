import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship } from "@/lib/core/types";
import { event, events, fact, facts, plural, toIso, uniq } from "../helpers";
import type { ProviderDefinition } from "../types";
import { ProviderSkip } from "../runtime";

/** Normalises a certificate name: lowercase, strips wildcard label, rejects junk. */
export function normalizeCertName(name: string): string | null {
  const cleaned = name.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!cleaned || cleaned.length > 253) return null;
  if (!/^[a-z0-9.-]+$/.test(cleaned) || !cleaned.includes(".")) return null;
  return cleaned;
}

function namesWithin(names: string[], domain: string): string[] {
  return uniq(names.map(normalizeCertName)).filter((n) => n === domain || n.endsWith(`.${domain}`)).sort();
}

function subdomainRelationships(domain: string, names: string[], provider: string): NormalizedRelationship[] {
  return names
    .filter((n) => n !== domain)
    .slice(0, 150)
    .map((n) => ({
      source: { type: "domain" as const, value: domain },
      target: { type: "domain" as const, value: n },
      type: "certificate-name",
      evidence: `Name appears in a Certificate Transparency log entry (${provider}).`,
    }));
}

// ---------------------------------------------------------------- Cert Spotter

const issuance = z
  .object({
    id: z.string(),
    cert_sha256: z.string().optional(),
    dns_names: z.array(z.string()).optional(),
    issuer: z.object({ friendly_name: z.string().optional(), name: z.string().optional() }).passthrough().optional(),
    not_before: z.string().optional(),
    not_after: z.string().optional(),
    revoked: z.boolean().optional(),
  })
  .passthrough();

export const certSpotter: ProviderDefinition = {
  id: "certspotter",
  code: "CS",
  name: "Cert Spotter",
  vendor: "SSLMate",
  category: "certificates",
  kind: "external",
  description: "Certificate Transparency search: certificates issued for a domain and its subdomains.",
  homepage: "https://sslmate.com/certspotter/",
  docs: "https://sslmate.com/help/reference/ct_search_api_v1",
  auth: { type: "optional", env: ["CERTSPOTTER_API_KEY"], header: "Authorization: Bearer", signup: "https://sslmate.com/signup?for=certspotter_api", benefit: "Higher query allowance." },
  endpoint: "REST · JSON · api.certspotter.com/v1/issuances",
  limits: "Unauthenticated use has a small hourly allowance; NOPS budgets 20 queries/hour without a key.",
  supports: ["DOMAIN"],
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 12_000,
  quotas: ({ hasKey }) => (hasKey ? [] : [{ limit: 20, windowSeconds: 3600, label: "unauthenticated allowance (20 queries per hour)" }]),
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(ctx.observable)}&include_subdomains=true&expand=dns_names&expand=issuer`;
    const { data } = await ctx.json(url, z.array(issuance), { headers: ctx.apiKey ? { authorization: `Bearer ${ctx.apiKey}` } : {} });
    if (!data.length) return { summary: "No certificates found in CT logs", facts: [], empty: true, listed: false };
    const names = namesWithin(data.flatMap((d) => d.dns_names ?? []), ctx.observable);
    const now = Date.now();
    const valid = data.filter((d) => d.not_after && new Date(d.not_after).getTime() > now && (!d.not_before || new Date(d.not_before).getTime() < now));
    const issuers = uniq(data.map((d) => d.issuer?.friendly_name ?? d.issuer?.name));
    const newest = [...data].sort((a, b) => (b.not_before ?? "").localeCompare(a.not_before ?? ""))[0];
    const wildcard = data.some((d) => (d.dns_names ?? []).some((n) => n.startsWith("*.")));
    const findings: NormalizedFinding[] = [];
    if (issuers.length >= 4) {
      findings.push({
        rule: "certs.many-issuers",
        severity: "INFO",
        category: "certificates",
        title: `Certificates issued by ${issuers.length} different CAs`,
        description: `CT logs show certificates for this domain from ${issuers.join(", ")}.`,
        rationale: "Multiple CAs are normal for large organisations and CDNs; unexpected issuers can reveal shadow IT or mis-issuance. A CAA record restricts which CAs may issue.",
        evidence: `Issuers: ${issuers.join(", ")}`,
      });
    }
    return {
      summary: `${plural(data.length, "certificate")} · ${plural(names.length, "name")} · ${valid.length} currently valid`,
      listed: true,
      facts: facts(
        fact("certificates", "Certificates (first page)", data.length, "number", true),
        fact("valid", "Currently valid", valid.length, "number", true),
        fact("names", "Distinct names", names.length, "number", true),
        fact("issuers", "Issuers", issuers, "list"),
        fact("wildcard", "Wildcard certificates", wildcard, "bool"),
        fact("latest", "Most recent issuance", toIso(newest?.not_before), "date")
      ),
      data: {
        kind: "ct-issuances",
        source: "certspotter",
        names,
        certificates: data.slice(0, 100).map((d) => ({
          id: d.id,
          sha256: d.cert_sha256,
          names: d.dns_names ?? [],
          issuer: d.issuer?.friendly_name ?? d.issuer?.name,
          notBefore: d.not_before,
          notAfter: d.not_after,
          revoked: d.revoked,
        })),
      },
      findings,
      relationships: subdomainRelationships(ctx.observable, names, "Cert Spotter"),
      timeline: events(event(newest?.not_before, "Most recent certificate issued", newest?.issuer?.friendly_name)),
      raw: data.slice(0, 50),
    };
  },
};

// ---------------------------------------------------------------- crt.sh

const crtEntry = z
  .object({
    id: z.number(),
    issuer_name: z.string().optional(),
    common_name: z.string().optional(),
    name_value: z.string(),
    not_before: z.string().optional(),
    not_after: z.string().optional(),
    serial_number: z.string().optional(),
    entry_timestamp: z.string().optional(),
  })
  .passthrough();

export const crtSh: ProviderDefinition = {
  id: "crtsh",
  code: "CRT",
  name: "crt.sh",
  vendor: "Sectigo",
  category: "certificates",
  kind: "external",
  description: "Certificate Transparency log search across all public CT logs, including historic certificates.",
  homepage: "https://crt.sh",
  auth: { type: "none" },
  endpoint: "REST · JSON · crt.sh/?output=json",
  limits: "Shared community service; queries can take 30 s or more.",
  supports: ["DOMAIN", "CERT_SHA256"],
  quick: ["CERT_SHA256"],
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 40_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    if (ctx.type === "CERT_SHA256") {
      const { data } = await ctx.json(`https://crt.sh/?q=${ctx.observable}&output=json`, z.array(crtEntry), { retries: 0 });
      if (!data.length) return { summary: "Certificate not found in CT logs", facts: [], empty: true, listed: false };
      const cert = data[0];
      const names = uniq(cert.name_value.split("\n").map(normalizeCertName));
      return {
        summary: `${cert.common_name ?? names[0] ?? "Certificate"} · ${cert.issuer_name?.match(/O=([^,]+)/)?.[1] ?? "issuer unknown"}`,
        listed: true,
        facts: facts(
          fact("cn", "Common name", cert.common_name, "mono", true),
          fact("names", "Subject alternative names", names, "list", true),
          fact("issuer", "Issuer", cert.issuer_name, "text", true),
          fact("notBefore", "Valid from", toIso(cert.not_before), "datetime"),
          fact("notAfter", "Valid until", toIso(cert.not_after), "datetime", true),
          fact("serial", "Serial", cert.serial_number, "mono"),
          fact("logged", "First logged", toIso(cert.entry_timestamp), "datetime")
        ),
        data: { kind: "ct-certificate", id: cert.id, names },
        relationships: names.slice(0, 50).map((n) => ({
          source: { type: "certificate", value: ctx.observable, label: cert.common_name },
          target: { type: "domain", value: n },
          type: "covers",
          evidence: "Subject alternative name in the logged certificate (crt.sh).",
        })),
        links: [{ label: "crt.sh certificate", url: `https://crt.sh/?id=${cert.id}` }],
        timeline: events(event(cert.not_before, "Certificate validity begins"), event(cert.not_after, "Certificate expires"), event(cert.entry_timestamp, "Logged to CT")),
        raw: data.slice(0, 5),
      };
    }

    if (ctx.observable.split(".").length > 6) throw new ProviderSkip("Hostname too deep for a CT wildcard search");
    const { data } = await ctx.json(`https://crt.sh/?q=${encodeURIComponent(`%.${ctx.observable}`)}&output=json&deduplicate=Y`, z.array(crtEntry), {
      retries: 0,
      maxBytes: 20 * 1024 * 1024,
    });
    if (!data.length) return { summary: "No certificates found in CT logs", facts: [], empty: true, listed: false };
    const names = namesWithin(data.flatMap((d) => d.name_value.split("\n")), ctx.observable);
    const now = Date.now();
    const valid = data.filter((d) => d.not_after && new Date(`${d.not_after}Z`).getTime() > now);
    const issuers = uniq(data.map((d) => d.issuer_name?.match(/O=([^,]+)/)?.[1]?.replace(/"/g, "")));
    const oldest = [...data].sort((a, b) => (a.not_before ?? "").localeCompare(b.not_before ?? ""))[0];
    return {
      summary: `${plural(data.length, "certificate")} · ${plural(names.length, "name")} (all-time)`,
      listed: true,
      facts: facts(
        fact("certificates", "Certificates (all-time)", data.length, "number", true),
        fact("valid", "Currently valid", valid.length, "number"),
        fact("names", "Distinct names", names.length, "number", true),
        fact("issuers", "Issuing organisations", issuers.slice(0, 10), "list"),
        fact("first", "Earliest certificate", toIso(oldest?.not_before), "date")
      ),
      data: {
        kind: "ct-issuances",
        source: "crtsh",
        names,
        certificates: data
          .slice(-100)
          .reverse()
          .map((d) => ({ id: String(d.id), names: d.name_value.split("\n"), issuer: d.issuer_name?.match(/O=([^,]+)/)?.[1], notBefore: d.not_before, notAfter: d.not_after })),
      },
      relationships: subdomainRelationships(ctx.observable, names, "crt.sh"),
      timeline: events(event(oldest?.not_before, "Earliest certificate in CT logs", oldest?.issuer_name?.match(/O=([^,]+)/)?.[1])),
      raw: { certificates: data.length, sample: data.slice(0, 20) },
    };
  },
};
