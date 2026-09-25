import "server-only";
import { z } from "zod";
import type { NormalizedFinding, NormalizedRelationship } from "@/lib/core/types";
import { feodoFeed, type FeodoEntry } from "@/lib/intel/feeds";
import { classifyIp } from "@/lib/observables/ip";
import { fact, facts, plural, uniq } from "../helpers";
import { ProviderSkip } from "../runtime";
import type { ProviderDefinition } from "../types";
import { dataOf } from "./shared";

const networkInfo = z.object({ status: z.string(), data: z.object({ asns: z.array(z.string()), prefix: z.string().nullable().optional() }).passthrough() });
const asOverview = z.object({ status: z.string(), data: z.object({ holder: z.string().nullable().optional() }).passthrough() });
const BASE = "https://stat.ripe.net/data";
const SOURCE = "sourceapp=nops-cyber-intelligence";

interface DnsData {
  kind: "dns";
  host: string;
  records: { type: string; values: string[] }[];
}

export interface HostingAddress {
  ip: string;
  scope: string;
  asns: string[];
  holder?: string;
  prefix?: string;
  feodo?: FeodoEntry[];
  error?: string;
}

export const hosting: ProviderDefinition = {
  id: "hosting",
  code: "HOST",
  name: "Hosting infrastructure",
  vendor: "Derived · DNS answers + RIPEstat + Feodo Tracker",
  category: "infrastructure",
  kind: "derived",
  description: "Maps the addresses a name resolves to onto their origin networks (BGP origin AS, announced prefix) and checks each one against the Feodo Tracker botnet C2 blocklist.",
  homepage: "https://stat.ripe.net",
  auth: { type: "none" },
  endpoint: "Derived · DNS A/AAAA → stat.ripe.net network-info & as-overview · Feodo feed",
  supports: ["DOMAIN", "URL", "EMAIL"],
  dependsOn: ["dns"],
  cacheTtlSeconds: 0,
  timeoutMs: 15_000,
  async run(ctx) {
    const dns = dataOf<DnsData>(ctx, "dns", "dns");
    if (!dns) throw new ProviderSkip("DNS resolution did not return any records to map");
    const addresses = uniq(dns.records.filter((r) => r.type === "A" || r.type === "AAAA").flatMap((r) => r.values)).slice(0, 6);
    if (!addresses.length) throw new ProviderSkip(`${dns.host} has no A or AAAA records`);

    const feed = await feodoFeed.get().catch(() => null);
    const holders = new Map<string, string | undefined>();
    let failures = 0;

    const mapped: HostingAddress[] = await Promise.all(
      addresses.map(async (ip) => {
        const scope = classifyIp(ip)?.scope ?? "unknown";
        const feodo = feed?.value.byIp.get(ip);
        if (scope !== "public") return { ip, scope, asns: [], feodo };
        try {
          const { data } = await ctx.json(`${BASE}/network-info/data.json?resource=${encodeURIComponent(ip)}&${SOURCE}`, networkInfo);
          return { ip, scope, asns: data.data.asns, prefix: data.data.prefix ?? undefined, feodo };
        } catch (err) {
          failures++;
          return { ip, scope, asns: [], feodo, error: (err as Error).message };
        }
      })
    );

    const asns = uniq(mapped.flatMap((m) => m.asns)).slice(0, 4);
    await Promise.all(
      asns.map(async (asn) => {
        try {
          const { data } = await ctx.json(`${BASE}/as-overview/data.json?resource=AS${asn}&${SOURCE}`, asOverview);
          holders.set(asn, data.data.holder ?? undefined);
        } catch {
          holders.set(asn, undefined);
        }
      })
    );
    for (const m of mapped) m.holder = m.asns.map((a) => holders.get(a)).find(Boolean);

    const findings: NormalizedFinding[] = [];
    const c2 = mapped.filter((m) => m.feodo?.length);
    if (c2.length) {
      const online = c2.some((m) => m.feodo!.some((e) => e.status === "online"));
      const families = uniq(c2.flatMap((m) => m.feodo!.map((e) => e.malware)));
      findings.push({
        rule: "hosting.resolves-to-c2",
        severity: online ? "CRITICAL" : "HIGH",
        category: "threat-intelligence",
        title: `${dns.host} resolves to a ${online ? "live " : ""}botnet C2 server`,
        description: `${c2.map((m) => m.ip).join(", ")} ${c2.length === 1 ? "is" : "are"} listed by Feodo Tracker as ${families.join(", ") || "botnet"} command-and-control.`,
        rationale: "Feodo Tracker verifies C2 servers from live malware configurations. A name pointing at one is almost certainly part of that infrastructure (or recently was).",
        evidence: c2.map((m) => `${m.ip}: ${m.feodo!.map((e) => `${e.malware ?? "botnet"} ${e.status ?? ""} port ${e.port ?? "?"}`).join("; ")}`).join(" · "),
        observable: c2[0].ip,
        remediation: "Block the name and addresses; investigate hosts that resolved or contacted them.",
        references: c2.map((m) => ({ label: `Feodo Tracker ${m.ip}`, url: `https://feodotracker.abuse.ch/browse/host/${m.ip}/` })),
      });
    }

    const relationships: NormalizedRelationship[] = mapped.flatMap((m) => [
      ...m.asns.map((asn) => ({
        source: { type: "ip" as const, value: m.ip },
        target: { type: "asn" as const, value: `AS${asn}`, label: holders.get(asn) },
        type: "announced-by",
        evidence: `Origin AS for ${m.prefix ?? m.ip} (RIPE RIS).`,
      })),
      ...(m.prefix ? [{ source: { type: "ip" as const, value: m.ip }, target: { type: "prefix" as const, value: m.prefix }, type: "announced-in", evidence: "Most specific announced prefix (RIPE RIS)." }] : []),
      ...(m.feodo ?? []).filter((e) => e.malware).slice(0, 1).map((e) => ({
        source: { type: "ip" as const, value: m.ip },
        target: { type: "malware" as const, value: e.malware! },
        type: "c2-for",
        evidence: `Feodo Tracker C2 (${e.status ?? "listed"}).`,
      })),
    ]);

    const networks = uniq(mapped.flatMap((m) => m.asns.map((a) => `AS${a}${holders.get(a) ? ` ${holders.get(a)}` : ""}`)));
    return {
      summary: networks.length ? `${plural(addresses.length, "address", "addresses")} in ${networks.slice(0, 2).join(", ")}${networks.length > 2 ? "…" : ""}` : `${plural(addresses.length, "address", "addresses")}, none publicly routed`,
      listed: true,
      partial: failures > 0 && failures < mapped.filter((m) => m.scope === "public").length,
      facts: facts(
        fact("networks", "Hosting networks", networks, "list", true),
        fact("prefixes", "Announced prefixes", uniq(mapped.map((m) => m.prefix)), "list"),
        fact("addresses", "Addresses mapped", addresses.length, "number"),
        fact("c2", "Listed C2 addresses", c2.length ? c2.map((m) => m.ip) : undefined, "list", true),
        fact("feodo", "Feodo feed checked", feed ? `${feed.value.entries.length} entries` : "Feed unavailable", "text")
      ),
      data: { kind: "hosting", host: dns.host, addresses: mapped, feodoChecked: Boolean(feed) },
      findings,
      relationships,
    };
  },
};
