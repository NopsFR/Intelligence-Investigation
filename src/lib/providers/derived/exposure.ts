import "server-only";
import { kevFeed, KEV_URL } from "@/lib/intel/feeds";
import { fact, facts, plural } from "../helpers";
import { ProviderSkip } from "../runtime";
import type { ProviderDefinition } from "../types";
import { dataOf } from "./shared";

interface InternetDbData {
  kind: "internetdb";
  ports: number[];
  vulns: string[];
  cpes: string[];
}

export const kevExposure: ProviderDefinition = {
  id: "kev-exposure",
  code: "KEVX",
  name: "Known-exploited exposure",
  vendor: "Derived · Shodan InternetDB × CISA KEV",
  category: "vulnerability",
  kind: "derived",
  description: "Cross-references CVEs that InternetDB associates with the host's exposed service versions against the CISA Known Exploited Vulnerabilities catalog.",
  homepage: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  auth: { type: "none" },
  endpoint: `Derived · InternetDB vulns ∩ ${new URL(KEV_URL).host} KEV feed`,
  supports: ["IPV4", "IPV6"],
  dependsOn: ["internetdb"],
  cacheTtlSeconds: 0,
  timeoutMs: 20_000,
  async run(ctx) {
    const idb = dataOf<InternetDbData>(ctx, "internetdb", "internetdb");
    if (!idb) throw new ProviderSkip("InternetDB has no data for this address");
    if (!idb.vulns.length) {
      return { summary: "No banner-matched CVEs to check", facts: facts(fact("vulns", "CVEs checked", 0, "number")), empty: true, listed: false };
    }
    const { value: kev } = await kevFeed.get();
    const hits = idb.vulns.map((id) => kev.index.get(id.toUpperCase())).filter((e): e is NonNullable<typeof e> => Boolean(e));
    if (!hits.length) {
      return {
        summary: `None of ${plural(idb.vulns.length, "CVE")} is in CISA KEV`,
        empty: true,
        listed: false,
        facts: facts(fact("checked", "CVEs checked", idb.vulns.length, "number", true), fact("catalog", "KEV catalog version", kev.catalogVersion, "mono")),
      };
    }
    const ransomware = hits.filter((h) => h.knownRansomwareCampaignUse?.toLowerCase() === "known");
    return {
      summary: `${plural(hits.length, "known-exploited CVE")} among exposed service versions`,
      listed: true,
      facts: facts(
        fact("kev", "Known-exploited CVEs", hits.map((h) => h.cveID), "list", true),
        fact("ransomware", "Used in ransomware campaigns", ransomware.map((h) => h.cveID), "list", true),
        fact("checked", "CVEs checked", idb.vulns.length, "number"),
        fact("catalog", "KEV catalog version", kev.catalogVersion, "mono")
      ),
      data: { kind: "kev-exposure", hits, checked: idb.vulns.length, catalogVersion: kev.catalogVersion },
      findings: [
        {
          rule: "exposure.kev-match",
          severity: ransomware.length ? "HIGH" : "MEDIUM",
          category: "vulnerability",
          title: `Exposed services match ${plural(hits.length, "actively exploited CVE")}`,
          description: `InternetDB associates this host's service versions with ${hits.map((h) => `${h.cveID} (${h.vendorProject} ${h.product})`).slice(0, 4).join(", ")}${hits.length > 4 ? "…" : ""}, which CISA lists as exploited in the wild.`,
          rationale:
            "The CVE association is inferred from banner versions and is not a confirmed vulnerability — backported patches often cause false matches. But exploitation of these CVEs is confirmed, so verifying the actual versions is urgent.",
          evidence: hits.map((h) => `${h.cveID} added to KEV ${h.dateAdded ?? ""}`.trim()).join("; "),
          evidenceData: { cves: hits.map((h) => h.cveID), ransomware: ransomware.map((h) => h.cveID) },
          confidence: "Unverified (version inference)",
          remediation: "Confirm installed versions on the host; patch or isolate anything that is genuinely affected.",
          references: hits.slice(0, 5).map((h) => ({ label: `NVD ${h.cveID}`, url: `https://nvd.nist.gov/vuln/detail/${h.cveID}` })),
        },
      ],
      relationships: hits.slice(0, 20).map((h) => ({
        source: { type: "ip" as const, value: ctx.observable },
        target: { type: "cve" as const, value: h.cveID, label: h.vulnerabilityName },
        type: "possibly-vulnerable-to",
        evidence: "InternetDB banner match; CVE listed in CISA KEV.",
      })),
    };
  },
};
