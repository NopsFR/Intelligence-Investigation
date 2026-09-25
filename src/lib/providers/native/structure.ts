import "server-only";
import type { NormalizedFinding, NormalizedRelationship } from "@/lib/core/types";
import { hostnameInfo } from "@/lib/observables/detect";
import { classifyIp, reverseDnsName } from "@/lib/observables/ip";
import { analyzeUrl } from "@/lib/observables/url";
import { fact, facts } from "../helpers";
import type { ProviderDefinition } from "../types";

const HOST_RULES = new Set(["host.idn", "host.idn-mixed-script", "host.deep-subdomain", "host.private-suffix"]);

export const urlAnalysis: ProviderDefinition = {
  id: "url-analysis",
  code: "URL",
  name: "URL structure",
  vendor: "Native · offline parser",
  category: "web",
  kind: "native",
  description:
    "Offline parsing of the URL: host type, registrable domain, userinfo tricks, punycode and mixed scripts, non-standard ports, executable paths and redirect parameters. No network access.",
  homepage: "https://url.spec.whatwg.org/",
  auth: { type: "none" },
  endpoint: "Local · WHATWG URL parser + Public Suffix List",
  supports: ["URL"],
  cacheTtlSeconds: 0,
  timeoutMs: 2_000,
  healthCheck: { observable: "https://example.com/", type: "URL" },
  async run(ctx) {
    const a = analyzeUrl(ctx.observable);
    if (!a) throw new Error("URL could not be parsed");
    const relationships: NormalizedRelationship[] = [];
    if (a.hostType === "domain") {
      relationships.push({ source: { type: "url", value: ctx.observable }, target: { type: "domain", value: a.hostname }, type: "hosted-on", evidence: "URL hostname." });
    } else {
      relationships.push({ source: { type: "url", value: ctx.observable }, target: { type: "ip", value: a.hostname }, type: "hosted-on", evidence: "URL host is an IP literal." });
    }
    for (const q of a.query.filter((q) => /^https?:\/\//i.test(q.value)).slice(0, 5)) {
      relationships.push({ source: { type: "url", value: ctx.observable }, target: { type: "url", value: q.value }, type: "embeds-url", evidence: `Query parameter ${q.key}.` });
    }
    return {
      summary: [a.hostType === "domain" ? a.registrableDomain ?? a.hostname : `${a.hostType.toUpperCase()} host`, a.protocol.toUpperCase(), a.fileExtension ? `.${a.fileExtension}` : null]
        .filter(Boolean)
        .join(" · "),
      listed: true,
      facts: facts(
        fact("host", "Host", a.hostname, "mono", true),
        fact("registrable", "Registrable domain", a.registrableDomain, "mono", true),
        fact("unicode", "Unicode hostname", a.unicodeHostname, "text"),
        fact("scheme", "Scheme", a.protocol, "mono"),
        fact("port", "Port", a.port, "number"),
        fact("path", "Path", a.pathname, "mono"),
        fact("extension", "File extension", a.fileExtension, "mono"),
        fact("params", "Query parameters", a.query.length || undefined, "number"),
        fact("suffix", "Public suffix", a.publicSuffix, "mono"),
        fact("platform", "Shared platform suffix", a.privateSuffix, "mono"),
        fact("length", "Length", a.length, "number")
      ),
      data: { kind: "url-analysis", ...a, findings: undefined },
      findings: a.findings,
      relationships,
    };
  },
};

export const hostnameAnalysis: ProviderDefinition = {
  id: "hostname-analysis",
  code: "HST",
  name: "Hostname structure",
  vendor: "Native · Public Suffix List",
  category: "dns",
  kind: "native",
  description: "Registrable domain, public suffix, subdomain depth, shared-platform suffixes and internationalised (punycode) labels. No network access.",
  homepage: "https://publicsuffix.org/",
  auth: { type: "none" },
  endpoint: "Local · Public Suffix List",
  supports: ["DOMAIN", "EMAIL"],
  cacheTtlSeconds: 0,
  timeoutMs: 2_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    const host = ctx.type === "EMAIL" ? ctx.observable.split("@")[1] : ctx.observable;
    const info = hostnameInfo(host);
    const findings: NormalizedFinding[] = (analyzeUrl(`http://${host}/`)?.findings ?? []).filter((f) => HOST_RULES.has(f.rule));
    const relationships: NormalizedRelationship[] = [];
    if (ctx.type === "EMAIL") {
      relationships.push({ source: { type: "email", value: ctx.observable }, target: { type: "domain", value: host }, type: "at-domain", evidence: "Address domain part." });
    }
    if (info.registrableDomain && info.registrableDomain !== host) {
      relationships.push({ source: { type: "domain", value: host }, target: { type: "domain", value: info.registrableDomain }, type: "subdomain-of", evidence: "Public Suffix List registrable domain." });
    }
    const depth = info.subdomain ? info.subdomain.split(".").length : 0;
    return {
      summary: `${info.registrableDomain ?? host}${depth ? ` · ${depth} subdomain level${depth === 1 ? "" : "s"}` : " · apex"}${info.isIdn ? " · IDN" : ""}`,
      listed: true,
      facts: facts(
        fact("registrable", "Registrable domain", info.registrableDomain, "mono", true),
        fact("suffix", "Public suffix", info.publicSuffix, "mono"),
        fact("subdomain", "Subdomain", info.subdomain, "mono"),
        fact("unicode", "Unicode form", info.unicode, "text", true),
        fact("platform", "Shared platform suffix", info.privateSuffix, "mono", true)
      ),
      data: { kind: "hostname", ...info, depth },
      findings,
      relationships,
    };
  },
};

export const addressContext: ProviderDefinition = {
  id: "address-context",
  code: "ADR",
  name: "Address classification",
  vendor: "Native · IANA special-purpose registries",
  category: "infrastructure",
  kind: "native",
  description: "Classifies the address against the IANA IPv4/IPv6 special-purpose registries (private, loopback, link-local, CGNAT, documentation, translation…).",
  homepage: "https://www.iana.org/assignments/iana-ipv4-special-registry/",
  auth: { type: "none" },
  endpoint: "Local · IANA special-purpose address registries",
  supports: ["IPV4", "IPV6"],
  cacheTtlSeconds: 0,
  timeoutMs: 2_000,
  healthCheck: { observable: "192.0.2.1", type: "IPV4" },
  async run(ctx) {
    const c = classifyIp(ctx.observable);
    if (!c) throw new Error("Address could not be parsed");
    const findings: NormalizedFinding[] = [];
    if (c.scope !== "public") {
      findings.push({
        rule: "ip.non-public",
        severity: "INFO",
        category: "infrastructure",
        title: `${c.description} (${c.range})`,
        description: `${c.address} is ${c.scope.replace(/-/g, " ")} address space and is not routable on the public internet.`,
        rationale:
          "Public threat-intelligence and reputation sources hold nothing meaningful for non-public space, so they were not queried. If this address appears in logs, look it up in your own asset inventory, DHCP and NAT records.",
        evidence: `${c.range} — ${c.reference}`,
        evidenceData: { scope: c.scope, range: c.range ?? "", reference: c.reference ?? "" },
      });
    }
    const relationships: NormalizedRelationship[] = c.embeddedIpv4
      ? [{ source: { type: "ip", value: c.address }, target: { type: "ip", value: c.embeddedIpv4 }, type: "embeds-ipv4", evidence: `${c.description} (${c.range}) carries this IPv4 address.` }]
      : [];
    return {
      summary: c.scope === "public" ? `Public IPv${c.version} unicast` : `${c.description} · not publicly routable`,
      listed: true,
      facts: facts(
        fact("version", "Version", `IPv${c.version}`, "text"),
        fact("canonical", "Canonical form", c.address !== ctx.observable ? c.address : undefined, "mono"),
        fact("scope", "Scope", c.scope, "text", true),
        fact("range", "Special-purpose range", c.range, "mono", true),
        fact("description", "Registry entry", c.scope === "public" ? undefined : c.description, "text"),
        fact("reference", "Reference", c.reference, "text"),
        fact("embedded", "Embedded IPv4", c.embeddedIpv4, "mono", true),
        fact("ptrName", "Reverse lookup name", reverseDnsName(c.address), "mono")
      ),
      data: { kind: "address", ...c },
      findings,
      relationships,
    };
  },
};
