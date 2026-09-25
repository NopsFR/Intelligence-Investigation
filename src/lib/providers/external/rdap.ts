import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship, ObservableType } from "@/lib/core/types";
import { providerJson } from "@/lib/net/provider-fetch";
import { hostnameInfo } from "@/lib/observables/detect";
import { ipv4ToNumber, isIpv4, parseIpv6 } from "@/lib/observables/ip";
import { daysBetween, event, events, fact, facts, toIso, uniq } from "../helpers";
import type { ProviderDefinition } from "../types";
import { ProviderSkip } from "../runtime";

// ---------------------------------------------------------------- IANA bootstrap (RFC 9224)

const bootstrapSchema = z.object({
  services: z.array(z.tuple([z.array(z.string()), z.array(z.string())])),
  publication: z.string().optional(),
});
type Registry = "dns" | "ipv4" | "ipv6" | "asn";
const bootstrapCache = new Map<Registry, { at: number; services: [string[], string[]][] }>();
const BOOTSTRAP_TTL = 24 * 60 * 60 * 1000;

async function bootstrap(registry: Registry, signal?: AbortSignal) {
  const cached = bootstrapCache.get(registry);
  if (cached && Date.now() - cached.at < BOOTSTRAP_TTL) return cached.services;
  const { data } = await providerJson(`https://data.iana.org/rdap/${registry}.json`, bootstrapSchema, { timeoutMs: 8000, signal });
  bootstrapCache.set(registry, { at: Date.now(), services: data.services });
  return data.services;
}

const preferHttps = (urls: string[]) => (urls.find((u) => u.startsWith("https://")) ?? urls[0]).replace(/\/?$/, "/");

function v4InCidr(ip: string, cidr: string): number {
  const [base, bits] = cidr.split("/");
  if (!isIpv4(base)) return -1;
  const prefix = Number(bits);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return ((ipv4ToNumber(ip) & mask) >>> 0) === ((ipv4ToNumber(base) & mask) >>> 0) ? prefix : -1;
}

function v6InCidr(ip: bigint, cidr: string): number {
  const [base, bits] = cidr.split("/");
  const b = parseIpv6(base);
  if (b === null) return -1;
  const prefix = BigInt(Number(bits));
  const shift = BigInt(128) - prefix;
  return ip >> shift === b >> shift ? Number(bits) : -1;
}

export async function rdapBaseUrl(observable: string, type: ObservableType, signal?: AbortSignal): Promise<{ base: string; query: string } | null> {
  if (type === "DOMAIN") {
    const tld = observable.split(".").pop()!;
    const services = await bootstrap("dns", signal);
    const hit = services.find(([tlds]) => tlds.includes(tld));
    return hit ? { base: preferHttps(hit[1]), query: `domain/${observable}` } : null;
  }
  if (type === "IPV4") {
    const services = await bootstrap("ipv4", signal);
    let best: { prefix: number; url: string } | null = null;
    for (const [cidrs, urls] of services) for (const c of cidrs) {
      const p = v4InCidr(observable, c);
      if (p > (best?.prefix ?? -1)) best = { prefix: p, url: preferHttps(urls) };
    }
    return best ? { base: best.url, query: `ip/${observable}` } : null;
  }
  if (type === "IPV6") {
    const ip = parseIpv6(observable);
    if (ip === null) return null;
    const services = await bootstrap("ipv6", signal);
    let best: { prefix: number; url: string } | null = null;
    for (const [cidrs, urls] of services) for (const c of cidrs) {
      const p = v6InCidr(ip, c);
      if (p > (best?.prefix ?? -1)) best = { prefix: p, url: preferHttps(urls) };
    }
    return best ? { base: best.url, query: `ip/${observable}` } : null;
  }
  if (type === "ASN") {
    const n = Number(observable.replace(/^AS/i, ""));
    const services = await bootstrap("asn", signal);
    for (const [ranges, urls] of services) {
      for (const r of ranges) {
        const [start, end] = r.split("-").map(Number);
        if (n >= start && n <= (end ?? start)) return { base: preferHttps(urls), query: `autnum/${n}` };
      }
    }
    return null;
  }
  return null;
}

// ---------------------------------------------------------------- Response parsing

const entitySchema: z.ZodType<RdapEntity> = z.lazy(() =>
  z
    .object({
      handle: z.string().optional(),
      roles: z.array(z.string()).optional(),
      vcardArray: z.tuple([z.string(), z.array(z.array(z.unknown()))]).optional(),
      publicIds: z.array(z.object({ type: z.string(), identifier: z.string() })).optional(),
      entities: z.array(entitySchema).optional(),
    })
    .passthrough()
);

interface RdapEntity {
  handle?: string;
  roles?: string[];
  vcardArray?: [string, unknown[][]];
  publicIds?: { type: string; identifier: string }[];
  entities?: RdapEntity[];
}

const eventSchema = z.object({ eventAction: z.string(), eventDate: z.string().optional() }).passthrough();

const rdapSchema = z
  .object({
    objectClassName: z.string().optional(),
    handle: z.string().optional(),
    ldhName: z.string().optional(),
    unicodeName: z.string().optional(),
    name: z.string().optional(),
    type: z.string().optional(),
    country: z.string().optional(),
    status: z.array(z.string()).optional(),
    events: z.array(eventSchema).optional(),
    entities: z.array(entitySchema).optional(),
    nameservers: z.array(z.object({ ldhName: z.string().optional() }).passthrough()).optional(),
    secureDNS: z.object({ delegationSigned: z.boolean().optional(), dsData: z.array(z.unknown()).optional() }).passthrough().optional(),
    startAddress: z.string().optional(),
    endAddress: z.string().optional(),
    ipVersion: z.string().optional(),
    parentHandle: z.string().optional(),
    cidr0_cidrs: z.array(z.object({ v4prefix: z.string().optional(), v6prefix: z.string().optional(), length: z.number() }).passthrough()).optional(),
    startAutnum: z.number().optional(),
    endAutnum: z.number().optional(),
    port43: z.string().optional(),
  })
  .passthrough();

interface Contact {
  role: string;
  name?: string;
  org?: string;
  email?: string;
  ianaId?: string;
}

function vcardField(vcard: RdapEntity["vcardArray"], field: string): string | undefined {
  const row = vcard?.[1]?.find((r) => r[0] === field);
  const value = row?.[3];
  if (typeof value === "string") return value.trim() || undefined;
  if (Array.isArray(value)) return value.filter((v) => typeof v === "string" && v).join(", ") || undefined;
  return undefined;
}

function collectContacts(entities: RdapEntity[] | undefined, out: Contact[] = []): Contact[] {
  for (const e of entities ?? []) {
    for (const role of e.roles ?? []) {
      out.push({
        role,
        name: vcardField(e.vcardArray, "fn"),
        org: vcardField(e.vcardArray, "org"),
        email: vcardField(e.vcardArray, "email"),
        ianaId: e.publicIds?.find((p) => /iana/i.test(p.type))?.identifier,
      });
    }
    collectContacts(e.entities, out);
  }
  return out;
}

const eventDate = (events: z.infer<typeof eventSchema>[] | undefined, action: string) => toIso(events?.find((e) => e.eventAction === action)?.eventDate);

const REDACTED = /redacted|privacy|not disclosed|data protected/i;

export const rdap: ProviderDefinition = {
  id: "rdap",
  code: "RDAP",
  name: "RDAP",
  vendor: "Regional & domain registries (via IANA bootstrap)",
  category: "infrastructure",
  kind: "external",
  description: "Registration Data Access Protocol: registrar, registration dates, network allocation and abuse contacts from the authoritative registry.",
  homepage: "https://www.iana.org/domains/rdap",
  docs: "https://datatracker.ietf.org/doc/html/rfc9224",
  auth: { type: "none" },
  endpoint: "RDAP · JSON · authoritative registry (IANA bootstrap)",
  limits: "Registry-specific rate limits apply; responses are cached.",
  supports: ["DOMAIN", "IPV4", "IPV6", "ASN", "URL", "EMAIL"],
  cacheTtlSeconds: 12 * 60 * 60,
  timeoutMs: 12_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    let queryType: ObservableType = ctx.type;
    let queryValue = ctx.observable;
    if (ctx.type === "URL" || ctx.type === "EMAIL" || ctx.type === "DOMAIN") {
      const host = ctx.type === "URL" ? new URL(ctx.observable).hostname : ctx.type === "EMAIL" ? ctx.observable.split("@")[1] : ctx.observable;
      if (isIpv4(host)) {
        queryType = "IPV4";
        queryValue = host;
      } else {
        const registrable = hostnameInfo(host).registrableDomain;
        if (!registrable) throw new ProviderSkip("No registrable domain for this hostname");
        queryType = "DOMAIN";
        queryValue = registrable;
      }
    }

    const target = await rdapBaseUrl(queryValue, queryType, ctx.signal);
    if (!target) throw new ProviderSkip(`No RDAP service is published for ${queryValue} in the IANA bootstrap registry`);
    const url = `${target.base}${target.query}`;
    const response = await ctx.request(url, { headers: { accept: "application/rdap+json, application/json" }, acceptStatus: [404] });
    if (response.status === 404) {
      return { summary: `${queryValue} is not registered (RDAP 404)`, facts: [fact("server", "RDAP server", new URL(target.base).host, "mono")!], empty: true, listed: false };
    }
    const d = ctx.parse(response, rdapSchema);
    const contacts = collectContacts(d.entities);
    const registrar = contacts.find((c) => c.role === "registrar");
    const registrant = contacts.find((c) => c.role === "registrant");
    const abuse = contacts.find((c) => c.role === "abuse" && c.email);
    const status = d.status ?? [];
    const server = new URL(target.base).host;
    const findings: NormalizedFinding[] = [];
    const relationships: NormalizedRelationship[] = [];

    if (queryType === "DOMAIN") {
      const registered = eventDate(d.events, "registration");
      const expires = eventDate(d.events, "expiration");
      const changed = eventDate(d.events, "last changed");
      const nameservers = uniq((d.nameservers ?? []).map((n) => n.ldhName?.toLowerCase().replace(/\.$/, "")));
      const ageDays = registered ? daysBetween(registered) : undefined;
      const expiresInDays = expires ? -daysBetween(expires) : undefined;
      const registrantOrg = registrant?.org ?? registrant?.name;
      const privacy = registrantOrg ? REDACTED.test(registrantOrg) : undefined;

      if (ageDays !== undefined && ageDays < 30) {
        findings.push({
          rule: "domain.newly-registered",
          severity: "MEDIUM",
          category: "registration",
          title: `Newly registered domain (${ageDays} day${ageDays === 1 ? "" : "s"} old)`,
          description: `${queryValue} was registered on ${registered!.slice(0, 10)}.`,
          rationale:
            "Most phishing and malware domains are used within days of registration and abandoned soon after. Youth alone is not malicious, but it removes the benefit of an established history.",
          evidence: `RDAP registration event: ${registered}`,
          evidenceData: { registered: registered!, ageDays },
          observable: queryValue !== ctx.observable ? queryValue : undefined,
        });
      } else if (ageDays !== undefined && ageDays < 180) {
        findings.push({
          rule: "domain.young",
          severity: "INFO",
          category: "registration",
          title: `Domain registered ${Math.round(ageDays / 30)} month(s) ago`,
          description: `${queryValue} was registered on ${registered!.slice(0, 10)}.`,
          evidence: `RDAP registration event: ${registered}`,
          observable: queryValue !== ctx.observable ? queryValue : undefined,
        });
      }
      if (expiresInDays !== undefined && expiresInDays < 0) {
        findings.push({
          rule: "domain.expired",
          severity: "MEDIUM",
          category: "registration",
          title: "Domain registration has expired",
          description: `The registry lists an expiration date of ${expires!.slice(0, 10)}.`,
          rationale: "Expired domains can be re-registered by anyone, allowing takeover of email and web traffic still pointed at them.",
          evidence: `RDAP expiration event: ${expires}`,
        });
      } else if (expiresInDays !== undefined && expiresInDays < 30) {
        findings.push({
          rule: "domain.expiring",
          severity: "LOW",
          category: "registration",
          title: `Domain registration expires in ${expiresInDays} days`,
          description: `The registration expires on ${expires!.slice(0, 10)}.`,
          rationale: "Lapsed registrations cause outages and can be sniped by third parties.",
          evidence: `RDAP expiration event: ${expires}`,
          remediation: "Renew the domain and enable auto-renewal.",
        });
      }
      const hold = status.filter((s) => /hold/i.test(s));
      if (hold.length) {
        findings.push({
          rule: "domain.hold",
          severity: "MEDIUM",
          category: "registration",
          title: `Domain is on ${hold.join(" / ")}`,
          description: "A hold status removes the domain from the DNS; registries and registrars apply it for abuse, disputes or non-payment.",
          rationale: "serverHold in particular is commonly applied to suspend abusive domains.",
          evidence: `RDAP status: ${status.join(", ")}`,
        });
      }
      const eppStatuses = status.some((s) => /prohibited|active|ok/i.test(s));
      if (eppStatuses && !status.some((s) => /transfer\s*prohibited/i.test(s)) && !hold.length) {
        findings.push({
          rule: "domain.no-transfer-lock",
          severity: "LOW",
          category: "registration",
          title: "Registrar transfer lock not set",
          description: "The domain has no clientTransferProhibited or serverTransferProhibited status.",
          rationale: "A transfer lock prevents unauthorised registrar transfers, a common step in domain hijacking.",
          evidence: `RDAP status: ${status.join(", ") || "none"}`,
          remediation: "Enable the registrar lock (clientTransferProhibited) at your registrar.",
        });
      }
      for (const ns of nameservers.slice(0, 8)) {
        relationships.push({ source: { type: "domain", value: queryValue }, target: { type: "domain", value: ns }, type: "delegated-to", evidence: `Nameserver listed by ${server}.` });
      }
      if (registrar?.name) {
        relationships.push({ source: { type: "domain", value: queryValue }, target: { type: "organization", value: registrar.name.toLowerCase(), label: registrar.name }, type: "registered-with", evidence: `Registrar entity in RDAP (${server}).` });
      }
      if (queryValue !== ctx.observable && ctx.type === "DOMAIN") {
        relationships.push({ source: { type: "domain", value: ctx.observable }, target: { type: "domain", value: queryValue }, type: "subdomain-of", evidence: "Registrable domain per the Public Suffix List." });
      }

      return {
        summary: `${registrar?.name ?? "Registrar unknown"}${registered ? ` · registered ${registered.slice(0, 10)}` : ""}`,
        listed: true,
        facts: facts(
          fact("domain", "Registered domain", queryValue, "mono", queryValue !== ctx.observable),
          fact("registrar", "Registrar", registrar?.name, "text", true),
          fact("ianaId", "IANA registrar ID", registrar?.ianaId, "mono"),
          fact("registered", "Registered", registered, "date", true),
          fact("age", "Age", ageDays !== undefined ? `${ageDays.toLocaleString()} days` : undefined, "text"),
          fact("expires", "Expires", expires, "date", true),
          fact("changed", "Last changed", changed, "date"),
          fact("registrant", "Registrant", registrantOrg ? (privacy ? "Redacted for privacy" : registrantOrg) : undefined, "text"),
          fact("nameservers", "Nameservers", nameservers, "list", true),
          fact("status", "Status", status, "list"),
          fact("dnssec", "DNSSEC delegation signed", d.secureDNS?.delegationSigned, "bool"),
          fact("abuse", "Abuse contact", abuse?.email, "mono"),
          fact("server", "RDAP server", server, "mono")
        ),
        data: { kind: "rdap-domain", domain: queryValue, registrar, registrant, abuse, registered, expires, changed, nameservers, status, secureDNS: d.secureDNS, contacts, server },
        findings,
        relationships,
        timeline: events(event(registered, "Domain registered", registrar?.name), event(changed, "Registration last changed"), event(expires, "Registration expires")),
        raw: d,
      };
    }

    // IP network or autonomous system
    const org = registrant?.org ?? registrant?.name ?? contacts.find((c) => c.role === "administrative")?.org ?? d.name;
    const cidrs = (d.cidr0_cidrs ?? []).map((c) => `${c.v4prefix ?? c.v6prefix}/${c.length}`);
    const registered = eventDate(d.events, "registration");
    const changed = eventDate(d.events, "last changed");

    if (queryType === "ASN") {
      if (org) relationships.push({ source: { type: "asn", value: ctx.observable }, target: { type: "organization", value: org.toLowerCase(), label: org }, type: "operated-by", evidence: `Registrant in RDAP (${server}).` });
      return {
        summary: `${d.name ?? ctx.observable}${org && org !== d.name ? ` · ${org}` : ""}`,
        listed: true,
        facts: facts(
          fact("name", "AS name", d.name, "mono", true),
          fact("org", "Organisation", org, "text", true),
          fact("country", "Country", d.country, "text"),
          fact("range", "AS range", d.startAutnum && d.endAutnum && d.startAutnum !== d.endAutnum ? `${d.startAutnum}–${d.endAutnum}` : undefined, "mono"),
          fact("registered", "Registered", registered, "date"),
          fact("changed", "Last changed", changed, "date"),
          fact("abuse", "Abuse contact", abuse?.email, "mono", true),
          fact("server", "RDAP server", server, "mono")
        ),
        data: { kind: "rdap-autnum", name: d.name, org, country: d.country, abuse, contacts, server },
        relationships,
        timeline: events(event(registered, "AS number registered", org ?? undefined), event(changed, "AS registration last changed")),
        raw: d,
      };
    }

    for (const cidr of cidrs.slice(0, 3)) {
      relationships.push({ source: { type: "ip", value: ctx.observable }, target: { type: "prefix", value: cidr }, type: "allocated-within", evidence: `Network ${d.handle ?? ""} registered at ${server}.` });
    }
    if (org) relationships.push({ source: { type: "ip", value: ctx.observable }, target: { type: "organization", value: org.toLowerCase(), label: org }, type: "allocated-to", evidence: `Registrant of ${d.handle ?? "the network"} (${server}).` });

    return {
      summary: `${org ?? d.name ?? "Network"}${cidrs[0] ? ` · ${cidrs[0]}` : ""}`,
      listed: true,
      facts: facts(
        fact("org", "Organisation", org, "text", true),
        fact("network", "Network name", d.name, "mono", true),
        fact("cidr", "Allocation", cidrs.length ? cidrs : d.startAddress && d.endAddress ? [`${d.startAddress} – ${d.endAddress}`] : undefined, "list", true),
        fact("type", "Allocation type", d.type, "text"),
        fact("country", "Country", d.country, "text", true),
        fact("handle", "Handle", d.handle, "mono"),
        fact("parent", "Parent network", d.parentHandle, "mono"),
        fact("registered", "Registered", registered, "date"),
        fact("changed", "Last changed", changed, "date"),
        fact("abuse", "Abuse contact", abuse?.email, "mono", true),
        fact("server", "RDAP server", server, "mono")
      ),
      data: { kind: "rdap-ip", name: d.name, org, cidrs, startAddress: d.startAddress, endAddress: d.endAddress, country: d.country, handle: d.handle, abuse, contacts, server },
      relationships,
      timeline: events(event(registered, "Network allocation registered", org ?? undefined), event(changed, "Allocation last changed")),
      raw: d,
    };
  },
};
