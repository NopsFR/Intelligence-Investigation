import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship, Severity } from "@/lib/core/types";
import { event, events, fact, facts, plural, toIso } from "../helpers";
import type { ProviderDefinition } from "../types";

// ---------------------------------------------------------------- AbuseIPDB

// https://www.abuseipdb.com/categories
const ABUSE_CATEGORIES: Record<number, string> = {
  1: "DNS compromise",
  2: "DNS poisoning",
  3: "Fraud orders",
  4: "DDoS attack",
  5: "FTP brute-force",
  6: "Ping of death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open proxy",
  10: "Web spam",
  11: "Email spam",
  12: "Blog spam",
  13: "VPN IP",
  14: "Port scan",
  15: "Hacking",
  16: "SQL injection",
  17: "Spoofing",
  18: "Brute-force",
  19: "Bad web bot",
  20: "Exploited host",
  21: "Web app attack",
  22: "SSH",
  23: "IoT targeted",
};

const abuseResponse = z.object({
  data: z
    .object({
      ipAddress: z.string(),
      isPublic: z.boolean().optional(),
      isWhitelisted: z.boolean().nullable().optional(),
      abuseConfidenceScore: z.number(),
      countryCode: z.string().nullable().optional(),
      countryName: z.string().nullable().optional(),
      usageType: z.string().nullable().optional(),
      isp: z.string().nullable().optional(),
      domain: z.string().nullable().optional(),
      hostnames: z.array(z.string()).nullable().optional(),
      isTor: z.boolean().optional(),
      totalReports: z.number().optional(),
      numDistinctUsers: z.number().optional(),
      lastReportedAt: z.string().nullable().optional(),
      reports: z
        .array(z.object({ reportedAt: z.string().optional(), comment: z.string().nullable().optional(), categories: z.array(z.number()).optional() }).passthrough())
        .optional(),
    })
    .passthrough(),
});

function abuseSeverity(score: number): Severity {
  if (score >= 75) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

export const abuseIpDb: ProviderDefinition = {
  id: "abuseipdb",
  code: "AIP",
  name: "AbuseIPDB",
  vendor: "AbuseIPDB",
  category: "reputation",
  kind: "external",
  description: "Crowd-sourced abuse reports with a 0–100 abuse confidence score, ISP and usage type.",
  homepage: "https://www.abuseipdb.com",
  docs: "https://docs.abuseipdb.com/",
  auth: { type: "required", env: ["ABUSEIPDB_API_KEY"], header: "Key", signup: "https://www.abuseipdb.com/register" },
  endpoint: "REST · JSON · api.abuseipdb.com/api/v2/check",
  limits: "Free tier: 1,000 checks per day.",
  supports: ["IPV4", "IPV6"],
  cacheTtlSeconds: 2 * 60 * 60,
  timeoutMs: 10_000,
  quotas: [{ limit: 1000, windowSeconds: 86_400, label: "free-tier limit of 1,000 checks per day" }],
  healthCheck: { observable: "1.1.1.1", type: "IPV4" },
  async run(ctx) {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ctx.observable)}&maxAgeInDays=90&verbose`;
    const { data } = await ctx.json(url, abuseResponse, { headers: { Key: ctx.apiKey!, accept: "application/json" } });
    const d = data.data;
    const reports = d.reports ?? [];
    const categoryCounts = new Map<string, number>();
    for (const r of reports) for (const c of r.categories ?? []) {
      const name = ABUSE_CATEGORIES[c] ?? `Category ${c}`;
      categoryCounts.set(name, (categoryCounts.get(name) ?? 0) + 1);
    }
    const topCategories = [...categoryCounts.entries()].sort((a, b) => b[1] - a[1]).map(([name, n]) => `${name} (${n})`);
    const findings: NormalizedFinding[] = [];
    if (d.abuseConfidenceScore > 0 && !d.isWhitelisted) {
      findings.push({
        rule: "reputation.abuseipdb.confidence",
        severity: abuseSeverity(d.abuseConfidenceScore),
        category: "reputation",
        title: `AbuseIPDB abuse confidence ${d.abuseConfidenceScore}%`,
        description: `${plural(d.totalReports ?? 0, "report")} from ${plural(d.numDistinctUsers ?? 0, "distinct reporter")} in the last 90 days.`,
        rationale:
          "The score is AbuseIPDB's own confidence that the address is abusive, weighted by reporter reputation and recency. Shared infrastructure (NAT, cloud, VPN) can collect reports for other tenants' behaviour.",
        evidence: topCategories.length ? `Reported for ${topCategories.slice(0, 5).join(", ")}.` : `Last reported ${d.lastReportedAt ?? "unknown"}.`,
        evidenceData: {
          score: d.abuseConfidenceScore,
          reports: d.totalReports ?? 0,
          reporters: d.numDistinctUsers ?? 0,
          lastReported: d.lastReportedAt ?? null,
          categories: topCategories.slice(0, 8),
        },
        confidence: `${d.abuseConfidenceScore}% (AbuseIPDB abuse confidence)`,
        references: [{ label: "AbuseIPDB report", url: `https://www.abuseipdb.com/check/${ctx.observable}` }],
      });
    }
    if (d.isTor) {
      findings.push({
        rule: "infrastructure.tor-exit",
        severity: "INFO",
        category: "infrastructure",
        title: "Tor exit node",
        description: "AbuseIPDB identifies this address as a Tor exit relay.",
        rationale: "Traffic from Tor exits originates from anonymous users; abuse reports are rarely attributable to the relay operator.",
        evidence: "isTor: true (AbuseIPDB)",
      });
    }
    return {
      summary: `Abuse confidence ${d.abuseConfidenceScore}% · ${plural(d.totalReports ?? 0, "report")}`,
      listed: (d.totalReports ?? 0) > 0,
      facts: facts(
        fact("score", "Abuse confidence", d.abuseConfidenceScore / 100, "percent", true),
        fact("reports", "Reports (90 days)", d.totalReports, "number", true),
        fact("reporters", "Distinct reporters", d.numDistinctUsers, "number"),
        fact("lastReported", "Last reported", toIso(d.lastReportedAt), "datetime"),
        fact("isp", "ISP", d.isp, "text", true),
        fact("usageType", "Usage type", d.usageType, "text", true),
        fact("domain", "Domain", d.domain, "mono"),
        fact("country", "Country", d.countryName ?? d.countryCode, "text"),
        fact("hostnames", "Hostnames", d.hostnames ?? [], "list"),
        fact("tor", "Tor exit", d.isTor, "bool"),
        fact("whitelisted", "Whitelisted", d.isWhitelisted ?? undefined, "bool"),
        fact("categories", "Report categories", topCategories.slice(0, 8), "list")
      ),
      data: { kind: "abuseipdb", ...d, reports: reports.slice(0, 25) },
      findings,
      timeline: events(event(d.lastReportedAt, "Last abuse report on AbuseIPDB")),
      raw: { ...d, reports: reports.slice(0, 25) },
    };
  },
};

// ---------------------------------------------------------------- GreyNoise Community

const greynoiseResponse = z
  .object({
    ip: z.string().optional(),
    noise: z.boolean().optional(),
    riot: z.boolean().optional(),
    classification: z.string().nullable().optional(),
    name: z.string().nullable().optional(),
    link: z.string().nullable().optional(),
    last_seen: z.string().nullable().optional(),
    message: z.string().optional(),
  })
  .passthrough();

export const greyNoise: ProviderDefinition = {
  id: "greynoise",
  code: "GN",
  name: "GreyNoise",
  vendor: "GreyNoise Intelligence",
  category: "reputation",
  kind: "external",
  description: "Separates internet background noise (mass scanners, crawlers) and common business services from targeted activity.",
  homepage: "https://www.greynoise.io",
  docs: "https://docs.greynoise.io/reference/get_v3-community-ip",
  auth: { type: "optional", env: ["GREYNOISE_API_KEY"], header: "key", signup: "https://viz.greynoise.io/signup", benefit: "Higher daily lookup allowance on the Community API." },
  endpoint: "REST · JSON · api.greynoise.io/v3/community",
  limits: "Community API: limited daily lookups without a key.",
  supports: ["IPV4"],
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 8_000,
  healthCheck: { observable: "8.8.8.8", type: "IPV4" },
  async run(ctx) {
    const response = await ctx.request(`https://api.greynoise.io/v3/community/${encodeURIComponent(ctx.observable)}`, {
      headers: ctx.apiKey ? { key: ctx.apiKey } : {},
      acceptStatus: [404],
    });
    const d = ctx.parse(response, greynoiseResponse);
    if (response.status === 404 || (!d.noise && !d.riot)) {
      return {
        summary: "Not observed scanning the internet",
        facts: facts(fact("noise", "Internet scanner", false, "bool"), fact("riot", "Common business service", false, "bool")),
        empty: true,
        listed: false,
        data: { kind: "greynoise", ...d },
        raw: d,
      };
    }
    const findings: NormalizedFinding[] = [];
    if (d.noise && d.classification === "malicious") {
      findings.push({
        rule: "reputation.greynoise.malicious-scanner",
        severity: "MEDIUM",
        category: "reputation",
        title: "Mass-scanning the internet with malicious intent (GreyNoise)",
        description: `GreyNoise observed this address opportunistically scanning or exploiting across the internet${d.last_seen ? `, last seen ${d.last_seen}` : ""}.`,
        rationale:
          "Opportunistic scanners hit everyone. Seeing this address in your logs is expected background noise rather than evidence you were specifically targeted — but blocking it is still reasonable.",
        evidence: `classification: malicious, noise: true${d.name ? `, actor: ${d.name}` : ""}`,
        references: d.link ? [{ label: "GreyNoise Visualizer", url: d.link }] : [],
      });
    } else if (d.noise && d.classification === "benign") {
      findings.push({
        rule: "reputation.greynoise.benign-scanner",
        severity: "INFO",
        category: "reputation",
        title: `Known benign scanner${d.name ? `: ${d.name}` : ""}`,
        description: "GreyNoise attributes this scanning activity to a known, benign organisation (research or search engine).",
        rationale: "Benign scanners explain many unsolicited connections and are usually safe to deprioritise.",
        evidence: `classification: benign, actor: ${d.name ?? "unknown"}`,
        references: d.link ? [{ label: "GreyNoise Visualizer", url: d.link }] : [],
      });
    }
    if (d.riot) {
      findings.push({
        rule: "reputation.greynoise.riot",
        severity: "INFO",
        category: "reputation",
        title: `Common business service${d.name ? ` (${d.name})` : ""}`,
        description: "GreyNoise RIOT identifies this address as belonging to a widely used business service.",
        rationale: "Traffic to RIOT services is overwhelmingly legitimate; alerts involving them are frequently false positives.",
        evidence: "riot: true (GreyNoise)",
      });
    }
    return {
      summary: d.riot ? `Business service · ${d.name ?? "RIOT"}` : `${d.classification ?? "unknown"} scanner${d.name ? ` · ${d.name}` : ""}`,
      listed: Boolean(d.noise),
      facts: facts(
        fact("classification", "Classification", d.classification, "text", true),
        fact("actor", "Actor / service", d.name, "text", true),
        fact("noise", "Internet scanner", d.noise, "bool"),
        fact("riot", "Common business service", d.riot, "bool"),
        fact("lastSeen", "Last seen", toIso(d.last_seen), "date")
      ),
      data: { kind: "greynoise", ...d },
      findings,
      links: d.link ? [{ label: "GreyNoise Visualizer", url: d.link }] : [],
      timeline: events(event(d.last_seen, "Last seen by GreyNoise sensors")),
      raw: d,
    };
  },
};

// ---------------------------------------------------------------- Shodan InternetDB

const internetDbResponse = z
  .object({
    ip: z.string().optional(),
    ports: z.array(z.number()).optional(),
    hostnames: z.array(z.string()).optional(),
    cpes: z.array(z.string()).optional(),
    tags: z.array(z.string()).optional(),
    vulns: z.array(z.string()).optional(),
    detail: z.string().optional(),
  })
  .passthrough();

const RISKY_PORTS: Record<number, { service: string; severity: Severity; why: string }> = {
  23: { service: "Telnet", severity: "HIGH", why: "Telnet sends credentials in cleartext and is a primary botnet recruitment vector." },
  445: { service: "SMB", severity: "HIGH", why: "Internet-facing SMB has driven major worm outbreaks and ransomware entry." },
  3389: { service: "RDP", severity: "HIGH", why: "Exposed RDP is among the most common initial-access vectors for ransomware." },
  5900: { service: "VNC", severity: "MEDIUM", why: "VNC is frequently deployed with weak or no authentication." },
  2375: { service: "Docker API (unencrypted)", severity: "HIGH", why: "An exposed Docker daemon grants host-level code execution." },
  6379: { service: "Redis", severity: "MEDIUM", why: "Redis is commonly exposed without authentication and abused for code execution." },
  9200: { service: "Elasticsearch", severity: "MEDIUM", why: "Exposed Elasticsearch clusters are a leading cause of data leaks." },
  27017: { service: "MongoDB", severity: "MEDIUM", why: "Exposed MongoDB instances are routinely wiped or ransomed." },
  11211: { service: "Memcached", severity: "MEDIUM", why: "Memcached is abused for amplification DDoS and data exposure." },
  1433: { service: "Microsoft SQL Server", severity: "MEDIUM", why: "Databases should not be reachable from the internet." },
  3306: { service: "MySQL", severity: "MEDIUM", why: "Databases should not be reachable from the internet." },
  5432: { service: "PostgreSQL", severity: "MEDIUM", why: "Databases should not be reachable from the internet." },
  21: { service: "FTP", severity: "LOW", why: "FTP transmits credentials in cleartext." },
};

const NOTABLE_TAGS: Record<string, { severity: Severity; title: string }> = {
  c2: { severity: "HIGH", title: "Tagged as command-and-control infrastructure" },
  compromised: { severity: "HIGH", title: "Tagged as compromised" },
  malware: { severity: "HIGH", title: "Tagged as hosting malware" },
  honeypot: { severity: "INFO", title: "Tagged as a honeypot" },
  tor: { severity: "INFO", title: "Tagged as Tor" },
  vpn: { severity: "INFO", title: "Tagged as VPN endpoint" },
  proxy: { severity: "INFO", title: "Tagged as proxy" },
};

export const internetDb: ProviderDefinition = {
  id: "internetdb",
  code: "IDB",
  name: "Shodan InternetDB",
  vendor: "Shodan",
  category: "infrastructure",
  kind: "external",
  description: "Open ports, hostnames, software (CPE) and vulnerability identifiers from Shodan's internet-wide scans.",
  homepage: "https://internetdb.shodan.io",
  docs: "https://internetdb.shodan.io/docs",
  auth: { type: "none" },
  endpoint: "REST · JSON · internetdb.shodan.io",
  limits: "Free, keyless; updated weekly.",
  terms: "Non-commercial use only.",
  supports: ["IPV4", "IPV6"],
  cacheTtlSeconds: 12 * 60 * 60,
  timeoutMs: 8_000,
  healthCheck: { observable: "1.1.1.1", type: "IPV4" },
  async run(ctx) {
    const response = await ctx.request(`https://internetdb.shodan.io/${encodeURIComponent(ctx.observable)}`, { acceptStatus: [404] });
    const d = ctx.parse(response, internetDbResponse);
    if (response.status === 404) {
      return { summary: "No open services recorded by Shodan", facts: [], empty: true, listed: false, raw: d };
    }
    const ports = [...(d.ports ?? [])].sort((a, b) => a - b);
    const vulns = d.vulns ?? [];
    const tags = d.tags ?? [];
    const findings: NormalizedFinding[] = [];

    const risky = ports.filter((p) => RISKY_PORTS[p]);
    for (const port of risky) {
      const r = RISKY_PORTS[port];
      findings.push({
        rule: `exposure.port.${port}`,
        severity: r.severity,
        category: "exposure",
        title: `${r.service} exposed to the internet (port ${port})`,
        description: `Shodan observed port ${port}/${r.service} accepting connections from the internet.`,
        rationale: r.why,
        evidence: `Open ports: ${ports.join(", ")}`,
        evidenceData: { port, service: r.service },
        remediation: `Restrict ${r.service} to VPN or allow-listed networks.`,
        references: [{ label: "Shodan host", url: `https://www.shodan.io/host/${ctx.observable}` }],
      });
    }
    if (vulns.length) {
      findings.push({
        rule: "exposure.internetdb.vulns",
        severity: "MEDIUM",
        category: "vulnerability",
        title: `${plural(vulns.length, "CVE")} associated with exposed service versions`,
        description: `Shodan matched service banners on this host to ${plural(vulns.length, "known vulnerability", "known vulnerabilities")}.`,
        rationale:
          "Shodan infers vulnerabilities from version banners without exploiting anything, so matches can be false positives (backported patches, altered banners). Treat them as leads to verify, not confirmed exposure.",
        evidence: vulns.slice(0, 12).join(", ") + (vulns.length > 12 ? "…" : ""),
        evidenceData: { cves: vulns.slice(0, 50), cpes: d.cpes ?? [] },
        confidence: "Unverified (banner-based)",
      });
    }
    for (const tag of tags) {
      const t = NOTABLE_TAGS[tag.toLowerCase()];
      if (!t) continue;
      findings.push({
        rule: `exposure.internetdb.tag.${tag.toLowerCase()}`,
        severity: t.severity,
        category: t.severity === "INFO" ? "infrastructure" : "threat-intelligence",
        title: `${t.title} (Shodan)`,
        description: `Shodan InternetDB applies the tag "${tag}" to this address.`,
        rationale: "Shodan tags are derived from scan fingerprints and third-party feeds.",
        evidence: `Tags: ${tags.join(", ")}`,
      });
    }

    const relationships: NormalizedRelationship[] = [
      ...(d.hostnames ?? []).slice(0, 12).map((h) => ({
        source: { type: "ip" as const, value: ctx.observable },
        target: { type: "domain" as const, value: h.toLowerCase() },
        type: "has-hostname",
        evidence: "Hostname observed for this IP by Shodan (reverse DNS or certificate).",
      })),
      ...vulns.slice(0, 20).map((cve) => ({
        source: { type: "ip" as const, value: ctx.observable },
        target: { type: "cve" as const, value: cve.toUpperCase() },
        type: "possibly-vulnerable-to",
        evidence: "Shodan banner-based CVE match (unverified).",
      })),
    ];

    return {
      summary: `${plural(ports.length, "open port")}${vulns.length ? ` · ${plural(vulns.length, "CVE")}` : ""}${tags.length ? ` · ${tags.join(", ")}` : ""}`,
      listed: true,
      facts: facts(
        fact("ports", "Open ports", ports.map(String), "list", true),
        fact("hostnames", "Hostnames", d.hostnames ?? [], "list", true),
        fact("vulns", "CVEs (banner-matched)", vulns.length, "number", true),
        fact("cpes", "Software (CPE)", d.cpes ?? [], "list"),
        fact("tags", "Tags", tags, "list")
      ),
      data: { kind: "internetdb", ports, hostnames: d.hostnames ?? [], cpes: d.cpes ?? [], tags, vulns },
      findings,
      relationships,
      links: [{ label: "Shodan host page", url: `https://www.shodan.io/host/${ctx.observable}` }],
      tags,
      raw: d,
    };
  },
};

