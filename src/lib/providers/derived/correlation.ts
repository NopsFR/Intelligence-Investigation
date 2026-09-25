import "server-only";
import { SEVERITY_RANK, type FactValue, type NormalizedFinding, type ProviderOutcome, type Severity } from "@/lib/core/types";
import { parseCvssVector, severityFromScore } from "@/lib/intel/cvss";
import { fact, facts, plural, uniq } from "../helpers";
import type { ProviderRunContext, ProviderDefinition } from "../types";
import { allOutcomes } from "./shared";

// Rules whose findings mean "this source has adverse intelligence on the observable".
const ADVERSE_PREFIXES = ["intel.", "malware.bazaar.", "malware.yaraify.", "reputation.abuseipdb.", "reputation.virustotal.detections", "reputation.greynoise.malicious-scanner", "hosting.resolves-to-c2"];
const NOT_ADVERSE = new Set(["intel.feodo.asn-hosts-c2", "intel.otx.pulses-allowlisted"]);
// Rules that are positive evidence of legitimacy.
const BENIGN_RULES = new Set(["malware.hashlookup.known-file", "reputation.greynoise.riot", "reputation.greynoise.benign-scanner", "intel.otx.pulses-allowlisted"]);
const INTEL_CATEGORIES = new Set(["threat-intel", "reputation", "malware"]);

export interface SourceSignal {
  provider: string;
  name: string;
  vendor: string;
  severity: Severity;
  rules: string[];
  titles: string[];
}

function isAdverse(f: NormalizedFinding): boolean {
  return ADVERSE_PREFIXES.some((p) => f.rule.startsWith(p)) && !NOT_ADVERSE.has(f.rule) && SEVERITY_RANK[f.severity] <= SEVERITY_RANK.MEDIUM;
}

/** Sources run by the same organisation (abuse.ch's five feeds) are not independent corroboration. */
function vendorOf(ctx: ProviderRunContext, id: string): string {
  if (id === "hosting") return "abuse.ch";
  return ctx.describe(id)?.vendor ?? id;
}

function signals(ctx: ProviderRunContext, outcomes: ProviderOutcome[], match: (f: NormalizedFinding) => boolean): SourceSignal[] {
  return outcomes
    .map((o) => {
      const hits = (o.result?.findings ?? []).filter(match);
      if (!hits.length) return null;
      const severity = hits.reduce<Severity>((best, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[best] ? f.severity : best), "INFO");
      return { provider: o.provider, name: ctx.describe(o.provider)?.name ?? o.provider, vendor: vendorOf(ctx, o.provider), severity, rules: uniq(hits.map((f) => f.rule)), titles: hits.map((f) => f.title) };
    })
    .filter((s): s is SourceSignal => Boolean(s));
}

interface CvssChoice {
  score: number;
  severity: string;
  vector?: string;
  version: string;
  source: string;
}

function chooseCvss(outcomes: ProviderOutcome[]): { chosen?: CvssChoice; all: CvssChoice[] } {
  const all: CvssChoice[] = [];
  const nvd = outcomes.find((o) => o.provider === "nvd")?.result?.data as { metrics?: { source?: string; type?: string; baseScore: number; baseSeverity?: string; vectorString?: string; version?: string }[] } | undefined;
  for (const m of nvd?.metrics ?? []) {
    all.push({ score: m.baseScore, severity: m.baseSeverity ?? "", vector: m.vectorString, version: m.version ?? "3.1", source: `NVD ${m.type === "Primary" ? "primary" : "secondary"} (${m.source ?? "unknown"})` });
  }
  const cve = outcomes.find((o) => o.provider === "cve-org")?.result?.data as
    | { cnaCvss?: { baseScore: number; baseSeverity?: string; vectorString?: string; version?: string }; adpCvss?: { baseScore: number; baseSeverity?: string; vectorString?: string; version?: string }; assigner?: string }
    | undefined;
  if (cve?.cnaCvss) all.push({ score: cve.cnaCvss.baseScore, severity: cve.cnaCvss.baseSeverity ?? "", vector: cve.cnaCvss.vectorString, version: cve.cnaCvss.version ?? "3.1", source: `CNA (${cve.assigner ?? "assigner"})` });
  if (cve?.adpCvss) all.push({ score: cve.adpCvss.baseScore, severity: cve.adpCvss.baseSeverity ?? "", vector: cve.adpCvss.vectorString, version: cve.adpCvss.version ?? "3.1", source: "CISA ADP" });
  // Preference: NVD primary, then the CNA's own score, then CISA ADP, then anything else.
  const chosen = all.find((c) => c.source.startsWith("NVD primary")) ?? all.find((c) => c.source.startsWith("CNA")) ?? all.find((c) => c.source === "CISA ADP") ?? all[0];
  return { chosen, all };
}

function cvssFinding(outcomes: ProviderOutcome[]): NormalizedFinding | null {
  const { chosen, all } = chooseCvss(outcomes);
  if (!chosen) return null;
  const level = severityFromScore(chosen.score, chosen.version);
  const parsed = parseCvssVector(chosen.vector);
  const m = (key: string) => parsed?.metrics.find((x) => x.key === key)?.value;
  const remote = m("AV") === "Network";
  const noAuth = (m("PR") ?? m("Au")) === "None";
  const noUser = m("UI") === "None";
  const traits = [remote ? "network-reachable" : m("AV")?.toLowerCase(), noAuth ? "no privileges required" : null, noUser ? "no user interaction" : null].filter(Boolean);
  const scores = uniq(all.map((c) => c.score));
  const evidenceData: Record<string, FactValue> = { score: chosen.score, version: chosen.version, source: chosen.source };
  if (chosen.vector) evidenceData.vector = chosen.vector;
  return {
    rule: "vuln.cvss",
    severity: level === "NONE" ? "INFO" : level,
    category: "vulnerability",
    title: `CVSS ${chosen.version.startsWith("4") ? "4.0" : chosen.version} base score ${chosen.score} (${level.toLowerCase()})`,
    description: `Scored by ${chosen.source}${traits.length ? `: ${traits.join(", ")}` : ""}.${scores.length > 1 ? ` Other scorers disagree (${all.filter((c) => c !== chosen).map((c) => `${c.source} ${c.score}`).join("; ")}).` : ""}`,
    rationale: "CVSS measures technical severity, not risk in your environment. Combine it with exploitation evidence (KEV, EPSS, SSVC) and whether you run an affected version.",
    evidence: chosen.vector ?? `Base score ${chosen.score}`,
    evidenceData,
  };
}

export const correlation: ProviderDefinition = {
  id: "correlation",
  code: "COR",
  name: "Cross-source correlation",
  vendor: "Derived · all sources in this investigation",
  category: "correlation",
  kind: "derived",
  description:
    "Weighs what the sources said together: independent corroboration, single-source detections, contradictions between sources, and combined signals such as a newly registered domain hosting a login form.",
  homepage: "https://attack.mitre.org",
  auth: { type: "none" },
  endpoint: "Local · evidence from every completed source",
  supports: ["IPV4", "IPV6", "DOMAIN", "URL", "EMAIL", "MD5", "SHA1", "SHA256", "CVE", "ASN", "CERT_SHA256"],
  // The engine makes this depend on every other step in the plan.
  dependsOn: ["*"],
  cacheTtlSeconds: 0,
  timeoutMs: 5_000,
  async run(ctx) {
    const outcomes = allOutcomes(ctx);
    const intel = outcomes.filter((o) => INTEL_CATEGORIES.has(ctx.describe(o.provider)?.category ?? "") || o.provider === "hosting");
    const answeredIntel = intel.filter((o) => ["SUCCESS", "PARTIAL", "EMPTY"].includes(o.status));
    const adverse = signals(ctx, outcomes, isAdverse);
    const benign = signals(ctx, outcomes, (f) => BENIGN_RULES.has(f.rule));
    const adverseVendors = uniq(adverse.map((s) => s.vendor));
    const silent = answeredIntel.filter((o) => !adverse.some((s) => s.provider === o.provider));
    const findings: NormalizedFinding[] = [];
    const highest = adverse.reduce<Severity | null>((best, s) => (!best || SEVERITY_RANK[s.severity] < SEVERITY_RANK[best] ? s.severity : best), null);

    if (adverseVendors.length >= 2) {
      findings.push({
        rule: "correlation.corroborated",
        severity: highest ?? "MEDIUM",
        category: "correlation",
        title: `Adverse intelligence from ${adverseVendors.length} independent sources`,
        description: `${adverse.map((s) => s.name).join(", ")} each hold adverse records for this observable.`,
        rationale: "Agreement between organisations that collect intelligence independently is much stronger evidence than any single listing.",
        evidence: adverse.map((s) => `${s.name}: ${s.titles[0]}`).join(" · "),
        evidenceData: { sources: adverse.map((s) => s.name), vendors: adverseVendors },
      });
    } else if (adverse.length && silent.length >= 2) {
      findings.push({
        rule: "correlation.single-source",
        severity: "INFO",
        category: "correlation",
        title: `Only ${adverseVendors[0]} reports adverse activity`,
        description: `${adverse.map((s) => s.name).join(", ")} flags this observable; ${silent.map((o) => ctx.describe(o.provider)?.name ?? o.provider).join(", ")} answered without adverse records.`,
        rationale: "Single-source detections are more likely to be stale, shared infrastructure or false positives. Check the listing's date and context before acting on it alone.",
        evidence: adverse.map((s) => `${s.name}: ${s.titles[0]}`).join(" · "),
      });
    }

    if (adverse.length && benign.length) {
      findings.push({
        rule: "correlation.conflict",
        severity: "LOW",
        category: "correlation",
        title: "Sources disagree about this observable",
        description: `${adverse.map((s) => s.name).join(", ")} report adverse activity, while ${benign.map((s) => `${s.name} (${s.titles[0]})`).join(", ")} indicate${benign.length === 1 ? "s" : ""} it is known-good or benign.`,
        rationale:
          "Conflicts usually mean shared infrastructure (CDNs, cloud hosts, popular software abused by malware) or a stale listing. Resolve it by checking dates, the exact indicator matched and the benign source's context.",
        evidence: [...adverse.map((s) => `adverse: ${s.rules.join(", ")}`), ...benign.map((s) => `benign: ${s.rules.join(", ")}`)].join(" · "),
      });
    }

    if (!adverse.length && answeredIntel.length >= 3) {
      findings.push({
        rule: "correlation.no-adverse-intel",
        severity: "INFO",
        category: "correlation",
        title: `No adverse records in ${plural(answeredIntel.length, "intelligence source")}`,
        description: `${answeredIntel.map((o) => ctx.describe(o.provider)?.name ?? o.provider).join(", ")} answered without adverse records.`,
        rationale: "Absence from intelligence feeds is not evidence of safety — new infrastructure is often unlisted. Weigh it together with registration age, hosting and content.",
        evidence: `${answeredIntel.length} answered, ${intel.length - answeredIntel.length} unavailable or not configured.`,
      });
    }

    const rules = new Set(outcomes.flatMap((o) => (o.result?.findings ?? []).map((f) => f.rule)));
    const young = rules.has("domain.newly-registered") || rules.has("domain.young");
    if (young && (rules.has("http.credential-form") || rules.has("http.form-posts-offsite"))) {
      const reg = outcomes.find((o) => o.provider === "rdap")?.result?.findings?.find((f) => f.rule.startsWith("domain.newly-registered") || f.rule === "domain.young");
      findings.push({
        rule: "correlation.new-domain-credential-capture",
        severity: rules.has("domain.newly-registered") ? "HIGH" : "MEDIUM",
        category: "correlation",
        title: "Recently registered domain collecting credentials",
        description: `The domain was registered recently (${reg?.title.toLowerCase() ?? "RDAP"}) and serves a page with a password field or a form that posts to another site.`,
        rationale: "Phishing kits are overwhelmingly hosted on domains days or weeks old. Legitimate login pages rarely live on brand-new registrations.",
        evidence: [reg?.evidence, rules.has("http.credential-form") ? "Password input present" : null, rules.has("http.form-posts-offsite") ? "Form posts off-site" : null].filter(Boolean).join(" · "),
      });
    }

    if (ctx.type === "CVE") {
      const f = cvssFinding(outcomes);
      if (f) findings.push(f);
    }

    const coverage = {
      planned: outcomes.length,
      answered: outcomes.filter((o) => ["SUCCESS", "PARTIAL", "EMPTY"].includes(o.status)).length,
      failed: outcomes.filter((o) => ["RATE_LIMITED", "AUTH_FAILED", "TIMEOUT", "NETWORK_ERROR", "INVALID_RESPONSE", "UNAVAILABLE"].includes(o.status)).length,
      notConfigured: outcomes.filter((o) => o.status === "NOT_CONFIGURED").length,
      skipped: outcomes.filter((o) => o.status === "SKIPPED").length,
    };
    const summary = adverseVendors.length >= 2
      ? `Corroborated by ${adverseVendors.length} independent sources`
      : adverse.length
        ? `Flagged by ${adverse.map((s) => s.name).join(", ")}`
        : answeredIntel.length
          ? `No adverse intelligence from ${plural(answeredIntel.length, "source")}`
          : `${coverage.answered} of ${coverage.planned} sources answered`;

    return {
      summary,
      empty: coverage.answered === 0,
      listed: adverse.length > 0,
      facts: facts(
        fact("adverse", "Sources with adverse records", adverse.map((s) => s.name), "list", true),
        fact("vendors", "Independent organisations", adverseVendors.length || undefined, "number"),
        fact("benign", "Sources indicating benign", benign.map((s) => s.name), "list", true),
        fact("silent", "Answered without adverse records", silent.map((o) => ctx.describe(o.provider)?.name ?? o.provider), "list"),
        fact("coverage", "Sources answered", `${coverage.answered} of ${coverage.planned}`, "text")
      ),
      data: {
        kind: "assessment",
        highest,
        adverse,
        benign,
        silent: silent.map((o) => o.provider),
        coverage,
        cvss: ctx.type === "CVE" ? chooseCvss(outcomes) : undefined,
      },
      findings,
    };
  },
};
