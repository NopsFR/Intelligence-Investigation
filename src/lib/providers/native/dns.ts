import "server-only";
import type { NormalizedFinding, NormalizedRelationship, ObservableType } from "@/lib/core/types";
import { query, resolve, RESOLVERS, type DnsResponse, type RecordType, type ResolverId } from "@/lib/dns/resolvers";
import { hostnameInfo } from "@/lib/observables/detect";
import { classifyIp, reverseDnsName } from "@/lib/observables/ip";
import { fact, facts, plural, uniq } from "../helpers";
import { ProviderSkip } from "../runtime";
import type { ProviderDefinition } from "../types";

/** The hostname a DNS-based analyser should look at for a given observable. */
export function hostFor(observable: string, type: ObservableType): string {
  if (type === "EMAIL") return observable.split("@")[1];
  if (type === "URL") {
    const host = new URL(observable).hostname.replace(/^\[|\]$/g, "");
    if (classifyIp(host)) throw new ProviderSkip("The URL uses an IP address; there is no hostname to resolve");
    return host;
  }
  return observable;
}

const PRIMARY_TYPES: RecordType[] = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA", "SOA"];
const COMPARED_TYPES: RecordType[] = ["A", "AAAA", "NS", "MX"];

export interface ResolverComparison {
  type: RecordType;
  answers: Partial<Record<ResolverId, string[] | null>>;
  consistent: boolean;
}

export const dnsRecords: ProviderDefinition = {
  id: "dns",
  code: "DNS",
  name: "DNS resolution",
  vendor: "Native · Cloudflare, Google & DNS.SB DoH",
  category: "dns",
  kind: "native",
  description: "Resolves A, AAAA, CNAME, NS, MX, TXT, CAA and SOA over DNS-over-HTTPS and cross-checks answers between three independent resolvers.",
  homepage: "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
  auth: { type: "none" },
  endpoint: "DoH · cloudflare-dns.com (JSON), dns.google (JSON), doh.dns.sb (RFC 8484)",
  supports: ["DOMAIN", "EMAIL", "URL"],
  cacheTtlSeconds: 5 * 60,
  timeoutMs: 10_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    const host = hostFor(ctx.observable, ctx.type);
    const errors: unknown[] = [];
    const primary = await Promise.all(
      PRIMARY_TYPES.map((t) =>
        query("cloudflare", host, t, ctx.signal)
          .catch(() => resolve(host, t, ctx.signal))
          .catch((err: unknown) => {
            errors.push(err);
            return null;
          })
      )
    );
    const failed = primary.filter((p) => p === null).length;
    // Surface the resolvers' own error (network, timeout, HTTP) so the state is classified correctly.
    if (failed === PRIMARY_TYPES.length) throw errors[0];

    const byType = new Map<RecordType, DnsResponse | null>(PRIMARY_TYPES.map((t, i) => [t, primary[i]]));
    const aResponse = byType.get("A");
    if (aResponse?.rcode === 3 && !aResponse.answers.some((a) => a.type === "CNAME")) {
      return {
        summary: `${host} does not exist (NXDOMAIN)`,
        facts: facts(fact("rcode", "Response", "NXDOMAIN", "mono", true), fact("resolver", "Resolver", RESOLVERS[aResponse.resolver].name, "text")),
        empty: true,
        listed: false,
        data: { kind: "dns", host, nxdomain: true, records: [], comparison: [] },
        findings: [
          {
            rule: "dns.nxdomain",
            severity: "INFO",
            category: "dns",
            title: "Domain does not resolve (NXDOMAIN)",
            description: `Resolvers report that ${host} does not exist in the DNS.`,
            rationale: "The name is unregistered, expired, suspended or deliberately removed; historic intelligence may still apply.",
            evidence: `${RESOLVERS[aResponse.resolver].name}: rcode ${aResponse.rcodeName}`,
          },
        ],
      };
    }

    const records = PRIMARY_TYPES.map((type) => {
      const response = byType.get(type);
      const answers = response?.answers.filter((a) => a.type === type) ?? [];
      return { type, values: answers.map((a) => a.data), ttl: answers[0]?.ttl, resolver: response?.resolver, error: response ? undefined : "lookup failed" };
    });
    const valuesOf = (type: RecordType) => records.find((r) => r.type === type)?.values ?? [];
    const cname = aResponse?.answers.filter((a) => a.type === "CNAME").map((a) => a.data) ?? [];

    const others = await Promise.all(
      COMPARED_TYPES.flatMap((type) =>
        (["google", "dnssb"] as ResolverId[]).map(async (resolver) => {
          try {
            const r = await query(resolver, host, type, ctx.signal);
            return { type, resolver, values: r.answers.filter((a) => a.type === type).map((a) => a.data) };
          } catch {
            return { type, resolver, values: null };
          }
        })
      )
    );
    const comparison: ResolverComparison[] = COMPARED_TYPES.map((type) => {
      const answers: ResolverComparison["answers"] = { cloudflare: byType.get(type) ? valuesOf(type) : null };
      for (const o of others.filter((x) => x.type === type)) answers[o.resolver] = o.values;
      const sets = Object.values(answers).filter((v): v is string[] => Array.isArray(v)).map((v) => [...v].sort().join("|"));
      return { type, answers, consistent: new Set(sets).size <= 1 };
    });

    const findings: NormalizedFinding[] = [];
    const a = valuesOf("A");
    const aaaa = valuesOf("AAAA");
    const mx = valuesOf("MX");

    if (cname.length && aResponse?.rcode === 3) {
      findings.push({
        rule: "dns.dangling-cname",
        severity: "HIGH",
        category: "dns",
        title: "Dangling CNAME — possible subdomain takeover",
        description: `${host} is an alias for ${cname.at(-1)}, which does not resolve.`,
        rationale:
          "When a CNAME points at a deprovisioned cloud resource (storage bucket, app service, CDN), anyone who claims that resource name can serve content on this hostname.",
        evidence: `CNAME chain: ${cname.join(" → ")}; target rcode NXDOMAIN`,
        evidenceData: { cname, rcode: "NXDOMAIN" },
        remediation: "Remove the CNAME record or reclaim the target resource.",
      });
    }

    const disjoint = comparison.filter((c) => {
      if (c.consistent || !["A", "AAAA"].includes(c.type)) return false;
      const lists = Object.values(c.answers).filter((v): v is string[] => Array.isArray(v) && v.length > 0);
      if (lists.length < 2) return false;
      return lists.every((l, i) => lists.every((m, j) => i === j || !l.some((x) => m.includes(x))));
    });
    if (disjoint.length) {
      findings.push({
        rule: "dns.resolver-disagreement",
        severity: "INFO",
        category: "dns",
        title: "Resolvers returned non-overlapping answers",
        description: `Cloudflare, Google and DNS.SB returned completely different ${disjoint.map((d) => d.type).join("/")} answers for ${host}.`,
        rationale:
          "This is normal for CDNs and geo-distributed services, which tailor answers by resolver location. In other contexts it can indicate fast-flux hosting or DNS manipulation.",
        evidence: disjoint.map((d) => Object.entries(d.answers).map(([r, v]) => `${r}: ${(v ?? []).join(", ") || "—"}`).join(" | ")).join(" ; "),
      });
    }

    const caa = valuesOf("CAA");
    const isApex = hostnameInfo(host).registrableDomain === host;
    if (!caa.length && isApex) {
      findings.push({
        rule: "dns.no-caa",
        severity: "INFO",
        category: "certificates",
        title: "No CAA record",
        description: "The domain does not publish a Certification Authority Authorization (CAA) record.",
        rationale: "Without CAA, any publicly trusted CA may issue certificates for the domain. CAA narrows mis-issuance risk to the CAs you actually use.",
        evidence: `CAA lookup for ${host} returned no records.`,
        remediation: 'Publish CAA records such as 0 issue "letsencrypt.org" for each CA you use.',
      });
    }

    const privateAnswers = [...a, ...aaaa].filter((ip) => classifyIp(ip) && classifyIp(ip)!.scope !== "public");
    if (privateAnswers.length) {
      findings.push({
        rule: "dns.private-address",
        severity: "MEDIUM",
        category: "dns",
        title: "Public DNS returns non-public addresses",
        description: `${host} resolves to ${privateAnswers.join(", ")} (${classifyIp(privateAnswers[0])!.description}).`,
        rationale: "Publishing internal addresses leaks network layout and is a building block of DNS-rebinding attacks against browsers.",
        evidence: `A/AAAA: ${[...a, ...aaaa].join(", ")}`,
      });
    }

    const relationships: NormalizedRelationship[] = [
      ...a.map((ip) => ({ source: { type: "domain" as const, value: host }, target: { type: "ip" as const, value: ip }, type: "resolves-to", evidence: "A record (DNS-over-HTTPS)." })),
      ...aaaa.map((ip) => ({ source: { type: "domain" as const, value: host }, target: { type: "ip" as const, value: ip }, type: "resolves-to", evidence: "AAAA record (DNS-over-HTTPS)." })),
      ...cname.map((target) => ({ source: { type: "domain" as const, value: host }, target: { type: "domain" as const, value: target }, type: "alias-of", evidence: "CNAME record." })),
      ...mx
        .map((v) => v.split(" ")[1])
        .filter((h) => h && h !== "." && h !== "")
        .map((h) => ({ source: { type: "domain" as const, value: host }, target: { type: "domain" as const, value: h }, type: "mail-handled-by", evidence: "MX record." })),
      ...valuesOf("NS").map((ns) => ({ source: { type: "domain" as const, value: host }, target: { type: "domain" as const, value: ns }, type: "delegated-to", evidence: "NS record." })),
    ];

    return {
      summary: `${plural(a.length + aaaa.length, "address", "addresses")} · ${plural(mx.length, "MX")} · ${plural(valuesOf("NS").length, "nameserver")}`,
      partial: failed > 0,
      listed: true,
      facts: facts(
        fact("a", "A", a, "list", true),
        fact("aaaa", "AAAA", aaaa, "list"),
        fact("cname", "CNAME chain", cname, "list", true),
        fact("mx", "MX", mx, "list", true),
        fact("ns", "NS", valuesOf("NS"), "list", true),
        fact("caa", "CAA", caa, "list"),
        fact("soa", "SOA", valuesOf("SOA")[0], "code"),
        fact("authenticated", "DNSSEC-validated answer", aResponse?.authenticated, "bool"),
        fact("consistency", "Resolver agreement", comparison.every((c) => c.consistent) ? "All resolvers agree" : `Differs on ${comparison.filter((c) => !c.consistent).map((c) => c.type).join(", ")}`, "text")
      ),
      data: { kind: "dns", host, records, comparison, cname, authenticated: aResponse?.authenticated ?? false },
      findings,
      relationships,
      raw: { records, comparison },
    };
  },
};

export const dnssec: ProviderDefinition = {
  id: "dnssec",
  code: "SEC",
  name: "DNSSEC",
  vendor: "Native · DoH (Cloudflare, Google)",
  category: "dns",
  kind: "native",
  description: "Checks for a DS record at the parent zone, DNSKEY publication and whether validating resolvers authenticate the zone.",
  homepage: "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
  auth: { type: "none" },
  endpoint: "DoH · DS / DNSKEY / AD-bit checks",
  supports: ["DOMAIN", "EMAIL"],
  quick: "none",
  cacheTtlSeconds: 30 * 60,
  timeoutMs: 10_000,
  healthCheck: { observable: "cloudflare.com", type: "DOMAIN" },
  async run(ctx) {
    const host = hostFor(ctx.observable, ctx.type);
    const zone = hostnameInfo(host).registrableDomain ?? host;
    const [ds, dnskey, aCf, aGoogle] = await Promise.all([
      resolve(zone, "DS", ctx.signal),
      resolve(zone, "DNSKEY", ctx.signal),
      query("cloudflare", zone, "SOA", ctx.signal).catch(() => null),
      query("google", zone, "SOA", ctx.signal).catch(() => null),
    ]);
    const dsRecords = ds.answers.filter((a) => a.type === "DS").map((a) => a.data);
    const keys = dnskey.answers.filter((a) => a.type === "DNSKEY");
    const ksk = keys.filter((k) => k.data.startsWith("257 "));
    const validated = Boolean(aCf?.authenticated || aGoogle?.authenticated);
    const servfail = (aCf?.rcode === 2 || aGoogle?.rcode === 2) && dsRecords.length > 0;
    const algorithms = uniq(dsRecords.map((d) => d.split(" ")[1]));
    const findings: NormalizedFinding[] = [];

    if (servfail) {
      findings.push({
        rule: "dnssec.bogus",
        severity: "HIGH",
        category: "dns",
        title: "DNSSEC validation is failing",
        description: `${zone} has a DS record, but validating resolvers return SERVFAIL.`,
        rationale: "A broken DNSSEC chain makes the domain unresolvable for every user behind a validating resolver — an outage, and sometimes a sign of tampering.",
        evidence: `DS: ${dsRecords.join("; ")} · Cloudflare rcode ${aCf?.rcodeName ?? "n/a"}, Google rcode ${aGoogle?.rcodeName ?? "n/a"}`,
        remediation: "Check that the DS record at the registrar matches a current DNSKEY and that signatures have not expired.",
      });
    } else if (!dsRecords.length) {
      findings.push({
        rule: "dnssec.unsigned",
        severity: "LOW",
        category: "dns",
        title: "DNSSEC is not enabled",
        description: `No DS record is published for ${zone} at the parent zone, so answers cannot be cryptographically authenticated.`,
        rationale: "DNSSEC protects against cache poisoning and on-path DNS tampering. Adoption is uneven, so this is hardening rather than an exposure.",
        evidence: `DS lookup for ${zone}: no records (rcode ${ds.rcodeName}).`,
        remediation: "Enable DNSSEC signing at your DNS provider and publish the DS record through the registrar.",
      });
    } else if (algorithms.some((a) => ["5", "7"].includes(a))) {
      findings.push({
        rule: "dnssec.legacy-algorithm",
        severity: "LOW",
        category: "dns",
        title: "DNSSEC uses an RSA/SHA-1 algorithm",
        description: `DS records reference algorithm ${algorithms.join(", ")} (RSASHA1 family), which RFC 8624 no longer recommends for signing.`,
        evidence: `DS: ${dsRecords.join("; ")}`,
        remediation: "Roll to ECDSAP256SHA256 (13) or ED25519 (15).",
      });
    }

    return {
      summary: servfail ? "Signed but failing validation" : dsRecords.length ? (validated ? "Signed and validated" : "Signed") : "Unsigned",
      listed: dsRecords.length > 0,
      facts: facts(
        fact("zone", "Zone", zone, "mono"),
        fact("signed", "DS at parent", dsRecords.length > 0, "bool", true),
        fact("validated", "Validated by resolvers", validated, "bool", true),
        fact("algorithms", "DS algorithms", algorithms, "list"),
        fact("ksk", "Key-signing keys", ksk.length, "number"),
        fact("keys", "DNSKEY records", keys.length, "number"),
        fact("ds", "DS records", dsRecords, "list")
      ),
      data: { kind: "dnssec", zone, ds: dsRecords, dnskeys: keys.length, validated, servfail },
      findings,
      raw: { ds: ds.answers, dnskey: keys.map((k) => k.data.slice(0, 40) + "…") },
    };
  },
};

export const reverseDns: ProviderDefinition = {
  id: "reverse-dns",
  code: "PTR",
  name: "Reverse DNS",
  vendor: "Native · DoH",
  category: "dns",
  kind: "native",
  description: "PTR lookup with forward-confirmation (FCrDNS).",
  homepage: "https://datatracker.ietf.org/doc/html/rfc1912#section-2.1",
  auth: { type: "none" },
  endpoint: "DoH · PTR in-addr.arpa / ip6.arpa",
  supports: ["IPV4", "IPV6"],
  cacheTtlSeconds: 30 * 60,
  timeoutMs: 8_000,
  skip: ({ observable }) => (classifyIp(observable)?.scope === "public" ? null : "Reverse DNS for non-public space is not meaningful on the public DNS"),
  healthCheck: { observable: "8.8.8.8", type: "IPV4" },
  async run(ctx) {
    const name = reverseDnsName(ctx.observable);
    if (!name) throw new ProviderSkip("Not an IP address");
    const ptr = await resolve(name, "PTR", ctx.signal);
    const hostnames = ptr.answers.filter((a) => a.type === "PTR").map((a) => a.data);
    if (!hostnames.length) return { summary: "No PTR record", facts: [fact("ptr", "PTR", "none", "text")!], empty: true, listed: false };
    const confirmation = await Promise.all(
      hostnames.slice(0, 3).map(async (h) => {
        try {
          const fwd = await resolve(h, ctx.observable.includes(":") ? "AAAA" : "A", ctx.signal);
          return fwd.answers.some((a) => a.data === ctx.observable);
        } catch {
          return false;
        }
      })
    );
    const confirmed = confirmation.some(Boolean);
    return {
      summary: `${hostnames[0]}${confirmed ? " · forward-confirmed" : ""}`,
      listed: true,
      facts: facts(
        fact("ptr", "PTR", hostnames, "list", true),
        fact("fcrdns", "Forward-confirmed", confirmed, "bool", true),
        fact("query", "Query name", name, "mono")
      ),
      data: { kind: "reverse-dns", hostnames, confirmed },
      relationships: hostnames.map((h) => ({
        source: { type: "ip" as const, value: ctx.observable },
        target: { type: "domain" as const, value: h },
        type: "has-ptr",
        evidence: confirmed ? "PTR record, forward-confirmed." : "PTR record (not forward-confirmed).",
      })),
      raw: ptr.answers,
    };
  },
};
