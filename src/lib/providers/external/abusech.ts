import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship, ObservableType } from "@/lib/core/types";
import { classifyIp } from "@/lib/observables/ip";
import { feodoFeed, FEODO_URL } from "@/lib/intel/feeds";
import { event, events, fact, facts, plural, toIso, uniq } from "../helpers";
import type { ProviderDefinition } from "../types";

const ABUSECH_ENV = ["ABUSECH_AUTH_KEY"];
const abusechAuth = (extraEnv: string) =>
  ({
    type: "required",
    env: [...ABUSECH_ENV, extraEnv],
    header: "Auth-Key",
    signup: "https://auth.abuse.ch/",
  }) as const;

const HASH_TYPES: ObservableType[] = ["MD5", "SHA1", "SHA256"];

function iocNode(ioc: string, iocType?: string): { type: "ip" | "domain" | "url" | "hash"; value: string } {
  const t = (iocType ?? "").toLowerCase();
  if (t.includes("ip")) return { type: "ip", value: ioc.split(":")[0] };
  if (t === "domain") return { type: "domain", value: ioc };
  if (t === "url") return { type: "url", value: ioc };
  return { type: "hash", value: ioc };
}

// ---------------------------------------------------------------- ThreatFox

const threatFoxIoc = z
  .object({
    id: z.union([z.string(), z.number()]).optional(),
    ioc: z.string(),
    ioc_type: z.string().optional(),
    threat_type: z.string().nullable().optional(),
    threat_type_desc: z.string().nullable().optional(),
    malware: z.string().nullable().optional(),
    malware_printable: z.string().nullable().optional(),
    malware_alias: z.string().nullable().optional(),
    malware_malpedia: z.string().nullable().optional(),
    confidence_level: z.number().nullable().optional(),
    first_seen: z.string().nullable().optional(),
    last_seen: z.string().nullable().optional(),
    reference: z.string().nullable().optional(),
    reporter: z.string().nullable().optional(),
    tags: z.array(z.string()).nullable().optional(),
  })
  .passthrough();

const threatFoxResponse = z.object({
  query_status: z.string(),
  data: z.union([z.array(threatFoxIoc), z.string(), z.null()]).optional(),
});

export const threatFox: ProviderDefinition = {
  id: "threatfox",
  code: "TFX",
  name: "ThreatFox",
  vendor: "abuse.ch",
  category: "threat-intel",
  kind: "external",
  description: "Community IOC database of malware command-and-control, payload and botnet infrastructure.",
  homepage: "https://threatfox.abuse.ch",
  docs: "https://threatfox.abuse.ch/api/",
  auth: abusechAuth("THREATFOX_API_KEY"),
  endpoint: "REST · JSON · threatfox-api.abuse.ch",
  limits: "Fair use. Free Auth-Key required since 2025.",
  terms: "CC0 data; abuse.ch fair-use policy applies.",
  supports: ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"],
  quick: ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"],
  cacheTtlSeconds: 30 * 60,
  timeoutMs: 10_000,
  healthCheck: { observable: "1.1.1.1", type: "IPV4" },
  async run(ctx) {
    const isHash = HASH_TYPES.includes(ctx.type);
    const body = isHash ? { query: "search_hash", hash: ctx.observable } : { query: "search_ioc", search_term: ctx.observable, exact_match: true };
    const { data } = await ctx.json("https://threatfox-api.abuse.ch/api/v1/", threatFoxResponse, {
      method: "POST",
      headers: { "Auth-Key": ctx.apiKey!, "content-type": "application/json" },
      body: JSON.stringify(body),
    });

    if (data.query_status !== "ok" || !Array.isArray(data.data) || data.data.length === 0) {
      return { summary: "No ThreatFox records", facts: [], empty: true, listed: false, raw: data };
    }

    const iocs = data.data;
    const families = uniq(iocs.map((i) => i.malware_printable ?? i.malware));
    const threatTypes = uniq(iocs.map((i) => i.threat_type_desc ?? i.threat_type));
    const confidences = iocs.map((i) => i.confidence_level).filter((c): c is number => typeof c === "number");
    const maxConfidence = confidences.length ? Math.max(...confidences) : undefined;
    const firstSeen = iocs.map((i) => toIso(i.first_seen)).filter(Boolean).sort()[0];
    const lastSeen = iocs.map((i) => toIso(i.last_seen)).filter(Boolean).sort().at(-1);

    const relationships: NormalizedRelationship[] = [];
    const selfType = isHash ? "hash" : ctx.type === "URL" ? "url" : ctx.type === "DOMAIN" ? "domain" : "ip";
    for (const family of families.slice(0, 5)) {
      relationships.push({
        source: { type: selfType, value: ctx.observable },
        target: { type: "malware", value: family },
        type: "associated-with",
        evidence: `ThreatFox lists this ${isHash ? "sample" : "indicator"} as ${family} infrastructure.`,
      });
    }
    if (isHash) {
      // search_hash returns IOCs (C2s, payload hosts) reported alongside this sample.
      for (const ioc of iocs.slice(0, 25)) {
        const node = iocNode(ioc.ioc, ioc.ioc_type);
        relationships.push({
          source: { type: "hash", value: ctx.observable },
          target: node,
          type: ioc.threat_type === "botnet_cc" ? "communicates-with" : "related-indicator",
          evidence: `ThreatFox ${ioc.threat_type_desc ?? ioc.threat_type ?? "IOC"} reported with this sample (${ioc.malware_printable ?? "unknown family"}).`,
        });
      }
    }

    const findings: NormalizedFinding[] = [
      {
        rule: "intel.threatfox.listed",
        severity: "HIGH",
        category: "threat-intelligence",
        title: isHash ? `Sample linked to ${plural(iocs.length, "ThreatFox IOC")}` : `Listed on ThreatFox as ${families[0] ?? "malware"} infrastructure`,
        description: `ThreatFox holds ${plural(iocs.length, "record")} for this ${isHash ? "hash" : "indicator"}${families.length ? `, associated with ${families.join(", ")}` : ""}.`,
        rationale:
          "ThreatFox entries are submitted by researchers and reviewed by abuse.ch; a listing means the indicator was observed in malware operations. Listings age: check the last-seen date before acting.",
        evidence: `Threat type: ${threatTypes.join(", ") || "unspecified"}; first seen ${firstSeen ?? "unknown"}, last seen ${lastSeen ?? "unknown"}.`,
        evidenceData: {
          records: iocs.length,
          families,
          threatTypes,
          firstSeen: firstSeen ?? null,
          lastSeen: lastSeen ?? null,
          ...(maxConfidence !== undefined ? { maxConfidence } : {}),
        },
        confidence: maxConfidence !== undefined ? `${maxConfidence}% (ThreatFox confidence level)` : undefined,
        remediation: isHash ? "Block the hash in EDR and hunt for the listed C2 infrastructure." : "Block at egress and search logs for connections during the listed window.",
        references: iocs
          .filter((i) => i.id)
          .slice(0, 3)
          .map((i) => ({ label: `ThreatFox IOC ${i.id}`, url: `https://threatfox.abuse.ch/ioc/${i.id}/` })),
      },
    ];

    return {
      summary: `${plural(iocs.length, "IOC record")} · ${families.join(", ") || "family unknown"}`,
      listed: true,
      facts: facts(
        fact("records", "IOC records", iocs.length, "number", true),
        fact("families", "Malware families", families, "list", true),
        fact("threatTypes", "Threat types", threatTypes, "list"),
        fact("confidence", "Highest confidence", maxConfidence !== undefined ? maxConfidence / 100 : undefined, "percent"),
        fact("firstSeen", "First seen", firstSeen, "datetime"),
        fact("lastSeen", "Last seen", lastSeen, "datetime"),
        fact("tags", "Tags", uniq(iocs.flatMap((i) => i.tags ?? [])).slice(0, 12), "list")
      ),
      data: { kind: "threatfox", iocs: iocs.slice(0, 50) },
      findings,
      relationships,
      timeline: events(event(firstSeen, "First reported to ThreatFox"), event(lastSeen, "Last seen by ThreatFox")),
      tags: uniq(iocs.flatMap((i) => i.tags ?? [])).slice(0, 20),
      raw: iocs.slice(0, 50),
    };
  },
};

// ---------------------------------------------------------------- URLhaus

const urlhausUrl = z
  .object({
    query_status: z.string(),
    id: z.union([z.string(), z.number()]).optional(),
    urlhaus_reference: z.string().optional(),
    url: z.string().optional(),
    url_status: z.string().optional(),
    host: z.string().optional(),
    date_added: z.string().optional(),
    last_online: z.string().nullable().optional(),
    threat: z.string().nullable().optional(),
    tags: z.array(z.string()).nullable().optional(),
    blacklists: z.record(z.string(), z.string()).optional(),
    payloads: z
      .array(
        z
          .object({
            firstseen: z.string().nullable().optional(),
            filename: z.string().nullable().optional(),
            file_type: z.string().nullable().optional(),
            response_sha256: z.string().nullable().optional(),
            signature: z.string().nullable().optional(),
          })
          .passthrough()
      )
      .nullable()
      .optional(),
  })
  .passthrough();

const urlhausHost = z
  .object({
    query_status: z.string(),
    urlhaus_reference: z.string().optional(),
    host: z.string().optional(),
    firstseen: z.string().nullable().optional(),
    url_count: z.union([z.string(), z.number()]).optional(),
    blacklists: z.record(z.string(), z.string()).optional(),
    urls: z
      .array(
        z
          .object({
            url: z.string(),
            url_status: z.string().optional(),
            date_added: z.string().optional(),
            threat: z.string().nullable().optional(),
            tags: z.array(z.string()).nullable().optional(),
          })
          .passthrough()
      )
      .nullable()
      .optional(),
  })
  .passthrough();

export const urlhaus: ProviderDefinition = {
  id: "urlhaus",
  code: "UH",
  name: "URLhaus",
  vendor: "abuse.ch",
  category: "threat-intel",
  kind: "external",
  description: "Tracks URLs and hosts used to distribute malware payloads.",
  homepage: "https://urlhaus.abuse.ch",
  docs: "https://urlhaus-api.abuse.ch/",
  auth: abusechAuth("URLHAUS_API_KEY"),
  endpoint: "REST · form POST · urlhaus-api.abuse.ch",
  limits: "Fair use. Free Auth-Key required since 2025.",
  terms: "CC0 data; abuse.ch fair-use policy applies.",
  supports: ["URL", "DOMAIN", "IPV4", "IPV6"],
  cacheTtlSeconds: 30 * 60,
  timeoutMs: 10_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    const headers = { "Auth-Key": ctx.apiKey!, "content-type": "application/x-www-form-urlencoded" };
    if (ctx.type === "URL") {
      const { data } = await ctx.json("https://urlhaus-api.abuse.ch/v1/url/", urlhausUrl, {
        method: "POST",
        headers,
        body: new URLSearchParams({ url: ctx.observable }).toString(),
      });
      if (data.query_status !== "ok") return { summary: "Not listed on URLhaus", facts: [], empty: true, listed: false, raw: data };
      const online = data.url_status === "online";
      const payloads = data.payloads ?? [];
      const signatures = uniq(payloads.map((p) => p.signature));
      return {
        summary: `${data.url_status ?? "listed"} · ${data.threat ?? "malware distribution"}`,
        listed: true,
        facts: facts(
          fact("status", "URL status", data.url_status, "text", true),
          fact("threat", "Threat", data.threat, "text", true),
          fact("host", "Host", data.host, "mono"),
          fact("added", "Added", toIso(data.date_added), "datetime"),
          fact("lastOnline", "Last online", toIso(data.last_online), "datetime"),
          fact("payloads", "Payloads observed", payloads.length, "number"),
          fact("signatures", "Payload families", signatures, "list"),
          fact("tags", "Tags", data.tags ?? [], "list")
        ),
        data: { kind: "urlhaus-url", ...data, payloads: payloads.slice(0, 20) },
        findings: [
          {
            rule: online ? "intel.urlhaus.online" : "intel.urlhaus.listed",
            severity: online ? "CRITICAL" : "HIGH",
            category: "threat-intelligence",
            title: online ? "Active malware distribution URL (URLhaus)" : "Known malware distribution URL (URLhaus)",
            description: `URLhaus lists this URL as ${data.url_status ?? "listed"}${data.threat ? ` for ${data.threat.replace(/_/g, " ")}` : ""}.`,
            rationale: online
              ? "URLhaus verified the URL was serving malicious content at its last check."
              : "The URL delivered malware in the past; offline status can change if the host is re-used.",
            evidence: `Added ${data.date_added ?? "unknown"}; ${payloads.length} payload(s)${signatures.length ? ` (${signatures.join(", ")})` : ""}.`,
            evidenceData: { status: data.url_status ?? null, threat: data.threat ?? null, payloads: payloads.length, signatures },
            remediation: "Block the URL and host at the web proxy; search proxy logs for prior access.",
            references: data.urlhaus_reference ? [{ label: "URLhaus entry", url: data.urlhaus_reference }] : [],
          },
        ],
        relationships: [
          ...(data.host ? [{ source: { type: "url" as const, value: ctx.observable }, target: { type: (classifyIp(data.host) ? "ip" : "domain") as "ip" | "domain", value: data.host }, type: "hosted-on", evidence: "URLhaus host field." }] : []),
          ...payloads
            .filter((p) => p.response_sha256)
            .slice(0, 10)
            .map((p) => ({
              source: { type: "url" as const, value: ctx.observable },
              target: { type: "hash" as const, value: p.response_sha256!, label: p.filename ?? undefined },
              type: "downloads",
              evidence: `URLhaus captured this payload${p.signature ? ` (${p.signature})` : ""} from the URL.`,
            })),
        ],
        timeline: events(event(data.date_added, "Added to URLhaus"), event(data.last_online, "Last seen online by URLhaus"), ...payloads.slice(0, 5).map((p) => event(p.firstseen, "Payload first seen", p.filename ?? undefined))),
        tags: data.tags ?? [],
        raw: data,
      };
    }

    const { data } = await ctx.json("https://urlhaus-api.abuse.ch/v1/host/", urlhausHost, {
      method: "POST",
      headers,
      body: new URLSearchParams({ host: ctx.observable }).toString(),
    });
    if (data.query_status !== "ok") return { summary: "Host not listed on URLhaus", facts: [], empty: true, listed: false, raw: data };
    const urls = data.urls ?? [];
    const online = urls.filter((u) => u.url_status === "online");
    const threats = uniq(urls.map((u) => u.threat));
    const selfType = ctx.type === "DOMAIN" ? "domain" : "ip";
    return {
      summary: `${plural(urls.length, "malicious URL")} on this host · ${online.length} online`,
      listed: true,
      facts: facts(
        fact("urls", "Malicious URLs", Number(data.url_count ?? urls.length), "number", true),
        fact("online", "Currently online", online.length, "number", true),
        fact("firstSeen", "First seen", toIso(data.firstseen), "datetime"),
        fact("threats", "Threats", threats, "list"),
        fact("tags", "Tags", uniq(urls.flatMap((u) => u.tags ?? [])).slice(0, 10), "list")
      ),
      data: { kind: "urlhaus-host", ...data, urls: urls.slice(0, 50) },
      findings: [
        {
          rule: online.length ? "intel.urlhaus.host-online" : "intel.urlhaus.host-listed",
          severity: online.length ? "HIGH" : "MEDIUM",
          category: "threat-intelligence",
          title: online.length ? `Host is serving ${plural(online.length, "active malware URL")}` : "Host previously served malware (URLhaus)",
          description: `URLhaus has recorded ${plural(urls.length, "malicious URL")} on this host since ${data.firstseen ?? "an unknown date"}.`,
          rationale: "Hosts that have distributed malware are often compromised or attacker-controlled and tend to be re-used.",
          evidence: `${online.length} of ${urls.length} URLs online at last check. Threats: ${threats.join(", ") || "unspecified"}.`,
          evidenceData: { urls: urls.length, online: online.length, threats },
          references: data.urlhaus_reference ? [{ label: "URLhaus host", url: data.urlhaus_reference }] : [],
        },
      ],
      relationships: urls.slice(0, 15).map((u) => ({
        source: { type: selfType, value: ctx.observable },
        target: { type: "url", value: u.url },
        type: "hosts",
        evidence: `URLhaus: ${u.threat ?? "malware"} URL (${u.url_status ?? "unknown status"}).`,
      })),
      timeline: events(event(data.firstseen, "First malicious URL recorded by URLhaus")),
      raw: { ...data, urls: urls.slice(0, 100) },
    };
  },
};

// ---------------------------------------------------------------- MalwareBazaar

const bazaarSample = z
  .object({
    sha256_hash: z.string(),
    sha1_hash: z.string().nullable().optional(),
    md5_hash: z.string().nullable().optional(),
    first_seen: z.string().nullable().optional(),
    last_seen: z.string().nullable().optional(),
    file_name: z.string().nullable().optional(),
    file_size: z.number().nullable().optional(),
    file_type_mime: z.string().nullable().optional(),
    file_type: z.string().nullable().optional(),
    reporter: z.string().nullable().optional(),
    origin_country: z.string().nullable().optional(),
    signature: z.string().nullable().optional(),
    imphash: z.string().nullable().optional(),
    tlsh: z.string().nullable().optional(),
    telfhash: z.string().nullable().optional(),
    gimphash: z.string().nullable().optional(),
    ssdeep: z.string().nullable().optional(),
    tags: z.array(z.string()).nullable().optional(),
    delivery_method: z.string().nullable().optional(),
    intelligence: z.record(z.string(), z.unknown()).nullable().optional(),
    yara_rules: z
      .array(z.object({ rule_name: z.string(), author: z.string().nullable().optional(), description: z.string().nullable().optional() }).passthrough())
      .nullable()
      .optional(),
    vendor_intel: z.record(z.string(), z.unknown()).nullable().optional(),
  })
  .passthrough();

const bazaarResponse = z.object({
  query_status: z.string(),
  data: z.array(bazaarSample).nullable().optional(),
});

export const malwareBazaar: ProviderDefinition = {
  id: "malwarebazaar",
  code: "MB",
  name: "MalwareBazaar",
  vendor: "abuse.ch",
  category: "malware",
  kind: "external",
  description: "Malware sample repository: family attribution, file metadata, similarity hashes and YARA hits.",
  homepage: "https://bazaar.abuse.ch",
  docs: "https://bazaar.abuse.ch/api/",
  auth: abusechAuth("MALWAREBAZAAR_API_KEY"),
  endpoint: "REST · form POST · mb-api.abuse.ch",
  limits: "Fair use. Free Auth-Key required since 2025. NOPS never downloads samples.",
  terms: "CC0 metadata; abuse.ch fair-use policy applies.",
  supports: HASH_TYPES,
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 10_000,
  healthCheck: { observable: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", type: "SHA256" },
  async run(ctx) {
    const { data } = await ctx.json("https://mb-api.abuse.ch/api/v1/", bazaarResponse, {
      method: "POST",
      headers: { "Auth-Key": ctx.apiKey!, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ query: "get_info", hash: ctx.observable }).toString(),
    });
    if (data.query_status !== "ok" || !data.data?.length) {
      return { summary: "Hash not in MalwareBazaar", facts: [], empty: true, listed: false, raw: data };
    }
    const s = data.data[0];
    const yara = s.yara_rules ?? [];
    const relationships: NormalizedRelationship[] = s.signature
      ? [{ source: { type: "hash", value: ctx.observable }, target: { type: "malware", value: s.signature }, type: "is-family", evidence: "MalwareBazaar signature (family attribution)." }]
      : [];
    return {
      summary: s.signature ? `${s.signature} · ${s.file_type ?? "sample"}` : `Known malware sample · ${s.file_type ?? "unknown type"}`,
      listed: true,
      facts: facts(
        fact("family", "Malware family", s.signature, "text", true),
        fact("fileType", "File type", s.file_type ?? s.file_type_mime, "text", true),
        fact("fileName", "Submitted file name", s.file_name, "mono"),
        fact("fileSize", "File size", s.file_size ?? undefined, "bytes"),
        fact("firstSeen", "First seen", toIso(s.first_seen), "datetime", true),
        fact("lastSeen", "Last seen", toIso(s.last_seen), "datetime"),
        fact("sha256", "SHA-256", s.sha256_hash, "mono"),
        fact("sha1", "SHA-1", s.sha1_hash, "mono"),
        fact("md5", "MD5", s.md5_hash, "mono"),
        fact("imphash", "Imphash", s.imphash, "mono"),
        fact("tlsh", "TLSH", s.tlsh, "mono"),
        fact("ssdeep", "ssdeep", s.ssdeep, "mono"),
        fact("delivery", "Delivery method", s.delivery_method, "text"),
        fact("tags", "Tags", s.tags ?? [], "list"),
        fact("yara", "YARA rules matched", yara.map((y) => y.rule_name), "list")
      ),
      data: { kind: "malwarebazaar", sample: { ...s, vendor_intel: undefined } },
      findings: [
        {
          rule: "malware.bazaar.known-sample",
          severity: "CRITICAL",
          category: "malware",
          title: s.signature ? `Known malware sample: ${s.signature}` : "Known malware sample",
          description: `This hash matches a sample catalogued in MalwareBazaar${s.signature ? ` and attributed to ${s.signature}` : ""}.`,
          rationale: "MalwareBazaar only accepts samples submitted as malware; an exact hash match is a direct identification, not a heuristic.",
          evidence: `First seen ${s.first_seen ?? "unknown"}; type ${s.file_type ?? "unknown"}; ${yara.length} YARA rule(s) matched.`,
          evidenceData: { family: s.signature ?? null, fileType: s.file_type ?? null, firstSeen: s.first_seen ?? null, yaraRules: yara.length, tags: s.tags ?? [] },
          remediation: "Quarantine affected hosts, block the hash, and pivot on imphash/TLSH for related samples.",
          references: [{ label: "MalwareBazaar sample", url: `https://bazaar.abuse.ch/sample/${s.sha256_hash}/` }],
        },
      ],
      relationships,
      timeline: events(event(s.first_seen, "First seen by MalwareBazaar", s.file_name ?? undefined), event(s.last_seen, "Last seen by MalwareBazaar")),
      tags: s.tags ?? [],
      raw: { ...s, vendor_intel: s.vendor_intel ? "[omitted: vendor sandbox reports]" : undefined },
    };
  },
};

// ---------------------------------------------------------------- YARAify

const yaraifyResponse = z.object({
  query_status: z.string(),
  data: z
    .union([
      z
        .object({
          metadata: z
            .object({
              file_size: z.number().nullable().optional(),
              file_type_mime: z.string().nullable().optional(),
              first_seen: z.string().nullable().optional(),
              last_seen: z.string().nullable().optional(),
              sightings: z.number().nullable().optional(),
              sha256_hash: z.string().nullable().optional(),
              md5_hash: z.string().nullable().optional(),
              sha1_hash: z.string().nullable().optional(),
              imphash: z.string().nullable().optional(),
              ssdeep: z.string().nullable().optional(),
              tlsh: z.string().nullable().optional(),
            })
            .passthrough(),
          tasks: z
            .array(
              z
                .object({
                  task_id: z.string().optional(),
                  time_stamp: z.string().optional(),
                  file_name: z.string().nullable().optional(),
                  clamav_results: z.array(z.string()).nullable().optional(),
                  static_results: z
                    .array(z.object({ rule_name: z.string(), author: z.string().nullable().optional(), description: z.string().nullable().optional(), reference: z.string().nullable().optional() }).passthrough())
                    .nullable()
                    .optional(),
                })
                .passthrough()
            )
            .nullable()
            .optional(),
        })
        .passthrough(),
      z.string(),
      z.null(),
    ])
    .optional(),
});

export const yaraify: ProviderDefinition = {
  id: "yaraify",
  code: "YFY",
  name: "YARAify",
  vendor: "abuse.ch",
  category: "malware",
  kind: "external",
  description: "YARA and ClamAV scan results for files submitted to abuse.ch's scanning service.",
  homepage: "https://yaraify.abuse.ch",
  docs: "https://yaraify.abuse.ch/api/",
  auth: { type: "optional", env: [...ABUSECH_ENV, "YARAIFY_API_KEY"], header: "Auth-Key", signup: "https://auth.abuse.ch/", benefit: "Authenticated access under your abuse.ch account." },
  endpoint: "REST · JSON · yaraify-api.abuse.ch",
  limits: "Fair use.",
  terms: "abuse.ch fair-use policy applies. NOPS only performs hash lookups; nothing is uploaded.",
  supports: HASH_TYPES,
  cacheTtlSeconds: 6 * 60 * 60,
  timeoutMs: 10_000,
  healthCheck: { observable: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", type: "SHA256" },
  async run(ctx) {
    const { data } = await ctx.json("https://yaraify-api.abuse.ch/api/v1/", yaraifyResponse, {
      method: "POST",
      headers: { "content-type": "application/json", ...(ctx.apiKey ? { "Auth-Key": ctx.apiKey } : {}) },
      body: JSON.stringify({ query: "lookup_hash", search_term: ctx.observable }),
    });
    if (data.query_status !== "ok" || !data.data || typeof data.data !== "object") {
      return { summary: "No YARAify scans for this hash", facts: [], empty: true, listed: false, raw: data };
    }
    const { metadata, tasks = [] } = data.data;
    const taskList = tasks ?? [];
    const rules = new Map<string, { rule: string; author?: string | null; description?: string | null }>();
    for (const t of taskList) for (const r of t.static_results ?? []) rules.set(r.rule_name, { rule: r.rule_name, author: r.author, description: r.description });
    const clamav = uniq(taskList.flatMap((t) => t.clamav_results ?? []));
    const ruleList = [...rules.values()];
    const findings: NormalizedFinding[] = [];
    if (ruleList.length || clamav.length) {
      findings.push({
        rule: "malware.yaraify.signature-hits",
        severity: clamav.length ? "HIGH" : "MEDIUM",
        category: "malware",
        title: `${plural(ruleList.length, "YARA rule")}${clamav.length ? ` and ${plural(clamav.length, "ClamAV signature")}` : ""} matched`,
        description: `Scans of this file on YARAify matched ${[...ruleList.map((r) => r.rule), ...clamav].slice(0, 6).join(", ")}${ruleList.length + clamav.length > 6 ? "…" : ""}.`,
        rationale:
          "Signature matches describe what a file contains (packers, capabilities, known families). Community YARA rules vary in precision — read the rule description before treating a match as attribution.",
        evidence: `${taskList.length} scan task(s); ${metadata.sightings ?? 0} sighting(s) since ${metadata.first_seen ?? "unknown"}.`,
        evidenceData: { yaraRules: ruleList.map((r) => r.rule), clamav, scans: taskList.length },
        references: [{ label: "YARAify", url: `https://yaraify.abuse.ch/sample/${metadata.sha256_hash ?? ctx.observable}/` }],
      });
    }
    return {
      summary: ruleList.length || clamav.length ? `${plural(ruleList.length, "YARA hit")} · ${plural(clamav.length, "ClamAV hit")}` : `${plural(taskList.length, "scan")} with no signature hits`,
      listed: true,
      facts: facts(
        fact("sightings", "Sightings", metadata.sightings ?? undefined, "number", true),
        fact("yara", "YARA rules", ruleList.map((r) => r.rule), "list", true),
        fact("clamav", "ClamAV signatures", clamav, "list", true),
        fact("mime", "MIME type", metadata.file_type_mime, "text"),
        fact("size", "File size", metadata.file_size ?? undefined, "bytes"),
        fact("firstSeen", "First seen", toIso(metadata.first_seen), "datetime"),
        fact("lastSeen", "Last seen", toIso(metadata.last_seen), "datetime"),
        fact("imphash", "Imphash", metadata.imphash, "mono"),
        fact("tlsh", "TLSH", metadata.tlsh, "mono")
      ),
      data: { kind: "yaraify", rules: ruleList, clamav, scans: taskList.length, metadata },
      findings,
      timeline: events(event(metadata.first_seen, "First seen by YARAify"), event(metadata.last_seen, "Last scanned by YARAify")),
      raw: { metadata, tasks: taskList.slice(0, 10) },
    };
  },
};

// ---------------------------------------------------------------- Feodo Tracker

export const feodoTracker: ProviderDefinition = {
  id: "feodo",
  code: "FEO",
  name: "Feodo Tracker",
  vendor: "abuse.ch",
  category: "threat-intel",
  kind: "external",
  description: "Blocklist of botnet command-and-control servers (Emotet, QakBot, Dridex and related families).",
  homepage: "https://feodotracker.abuse.ch",
  docs: "https://feodotracker.abuse.ch/blocklist/",
  auth: { type: "none" },
  endpoint: "Feed · JSON · feodotracker.abuse.ch/downloads/ipblocklist.json",
  limits: "Public download; cached for 15 minutes.",
  terms: "CC0; abuse.ch fair-use policy applies.",
  supports: ["IPV4", "ASN"],
  cacheTtlSeconds: 0,
  timeoutMs: 12_000,
  healthCheck: { observable: "1.1.1.1", type: "IPV4" },
  async run(ctx) {
    const { value: feed, fetchedAt } = await feodoFeed.get();
    ctx.note(`Feed ${FEODO_URL} with ${feed.entries.length} entries, retrieved ${new Date(fetchedAt).toISOString()}`);

    if (ctx.type === "ASN") {
      const asn = Number(ctx.observable.replace(/^AS/i, ""));
      const matches = feed.entries.filter((e) => e.as_number === asn);
      if (!matches.length) {
        return { summary: `No listed C2 servers in ${ctx.observable}`, facts: [fact("feedSize", "Entries in feed", feed.entries.length, "number")!], empty: true, listed: false };
      }
      const online = matches.filter((m) => m.status === "online");
      return {
        summary: `${plural(matches.length, "botnet C2 server")} listed in this ASN · ${online.length} online`,
        listed: true,
        facts: facts(
          fact("servers", "Listed C2 servers", matches.length, "number", true),
          fact("online", "Online", online.length, "number", true),
          fact("families", "Families", uniq(matches.map((m) => m.malware)), "list", true)
        ),
        data: { kind: "feodo-asn", entries: matches },
        findings: [
          {
            rule: "intel.feodo.asn-hosts-c2",
            severity: online.length ? "MEDIUM" : "LOW",
            category: "threat-intelligence",
            title: `${plural(matches.length, "botnet C2 server")} listed in ${ctx.observable}`,
            description: `Feodo Tracker lists ${matches.map((m) => m.ip_address).slice(0, 5).join(", ")}${matches.length > 5 ? "…" : ""} in this network.`,
            rationale: "C2 density indicates how much malicious hosting an operator tolerates; it is context about the network, not a verdict on every address in it.",
            evidence: `${online.length} online, ${matches.length - online.length} offline.`,
            evidenceData: { servers: matches.map((m) => m.ip_address), families: uniq(matches.map((m) => m.malware)) },
          },
        ],
        relationships: matches.slice(0, 20).map((m) => ({
          source: { type: "asn", value: ctx.observable },
          target: { type: "ip", value: m.ip_address },
          type: "announces",
          evidence: `Feodo Tracker: ${m.malware ?? "botnet"} C2 (${m.status ?? "unknown"}).`,
        })),
      };
    }

    const entries = feed.byIp.get(ctx.observable) ?? [];
    if (!entries.length) {
      return {
        summary: "Not on the Feodo Tracker C2 blocklist",
        facts: [fact("feedSize", "Entries in current feed", feed.entries.length, "number")!],
        empty: true,
        listed: false,
      };
    }
    const e = entries[0];
    const online = entries.some((x) => x.status === "online");
    return {
      summary: `${e.malware ?? "Botnet"} C2 · ${e.status ?? "listed"}`,
      listed: true,
      facts: facts(
        fact("malware", "Malware family", e.malware, "text", true),
        fact("status", "Status", e.status, "text", true),
        fact("ports", "C2 ports", uniq(entries.map((x) => (x.port != null ? String(x.port) : null))), "list"),
        fact("asn", "AS", e.as_number ? `AS${e.as_number} ${e.as_name ?? ""}`.trim() : undefined, "text"),
        fact("country", "Country", e.country, "text"),
        fact("firstSeen", "First seen", toIso(e.first_seen), "datetime"),
        fact("lastOnline", "Last online", toIso(e.last_online), "date")
      ),
      data: { kind: "feodo-ip", entries },
      findings: [
        {
          rule: online ? "intel.feodo.c2-online" : "intel.feodo.c2-listed",
          severity: online ? "CRITICAL" : "HIGH",
          category: "threat-intelligence",
          title: `${online ? "Active" : "Listed"} ${e.malware ?? "botnet"} command-and-control server`,
          description: `Feodo Tracker lists this address as a ${e.malware ?? "botnet"} C2 on port ${entries.map((x) => x.port).filter(Boolean).join(", ") || "unknown"}.`,
          rationale: "Feodo Tracker publishes C2 servers it has verified by tracking live malware configurations; traffic to them indicates an infected host.",
          evidence: `Status ${e.status ?? "unknown"}; first seen ${e.first_seen ?? "unknown"}; last online ${e.last_online ?? "unknown"}.`,
          evidenceData: { malware: e.malware ?? null, status: e.status ?? null, firstSeen: e.first_seen ?? null, lastOnline: e.last_online ?? null },
          remediation: "Block at the perimeter and treat any internal host that contacted it as compromised.",
          references: [{ label: "Feodo Tracker", url: `https://feodotracker.abuse.ch/browse/host/${ctx.observable}/` }],
        },
      ],
      relationships: [
        ...(e.malware ? [{ source: { type: "ip" as const, value: ctx.observable }, target: { type: "malware" as const, value: e.malware }, type: "c2-for", evidence: "Feodo Tracker C2 attribution." }] : []),
        ...(e.as_number ? [{ source: { type: "ip" as const, value: ctx.observable }, target: { type: "asn" as const, value: `AS${e.as_number}`, label: e.as_name ?? undefined }, type: "announced-by", evidence: "Feodo Tracker AS field." }] : []),
      ],
      timeline: events(event(e.first_seen, "First seen as C2 by Feodo Tracker"), event(e.last_online, "Last online as C2")),
      raw: entries,
    };
  },
};
