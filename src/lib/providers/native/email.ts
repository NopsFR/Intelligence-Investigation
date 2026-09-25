import "server-only";
import type { NormalizedFinding, NormalizedRelationship } from "@/lib/core/types";
import { lookup, resolve } from "@/lib/dns/resolvers";
import {
  COMMON_DKIM_SELECTORS,
  SPF_LOOKUP_TERMS,
  estimateRsaBits,
  parseDmarc,
  parseMtaStsPolicy,
  parseSpf,
  parseTagList,
  type ParsedSpf,
} from "@/lib/dns/email-parse";
import { hostnameInfo } from "@/lib/observables/detect";
import { targetRequest } from "@/lib/net/target";
import { fact, facts } from "../helpers";
import type { ProviderDefinition } from "../types";
import { hostFor } from "./dns";

async function txt(name: string, signal: AbortSignal): Promise<string[]> {
  try {
    return await lookup(name, "TXT", signal);
  } catch {
    return [];
  }
}

interface SpfEvaluation {
  record?: string;
  parsed?: ParsedSpf;
  lookups: number;
  voidLookups: number;
  includes: string[];
  errors: string[];
  multiple: boolean;
}

/** Counts DNS-querying terms recursively, as a receiver would (RFC 7208 §4.6.4). */
async function evaluateSpf(domain: string, signal: AbortSignal): Promise<SpfEvaluation> {
  const records = (await txt(domain, signal)).filter((r) => r.toLowerCase().startsWith("v=spf1"));
  const result: SpfEvaluation = { lookups: 0, voidLookups: 0, includes: [], errors: [], multiple: records.length > 1 };
  if (!records.length) return result;
  result.record = records[0];
  result.parsed = parseSpf(records[0]);
  result.errors.push(...result.parsed.errors);

  const visited = new Set<string>([domain]);
  const walk = async (parsed: ParsedSpf, depth: number): Promise<void> => {
    for (const term of [...parsed.terms, ...(parsed.redirect ? [{ mechanism: "redirect", value: parsed.redirect, qualifier: "+" as const }] : [])]) {
      if (!SPF_LOOKUP_TERMS.has(term.mechanism)) continue;
      result.lookups++;
      if ((term.mechanism === "include" || term.mechanism === "redirect") && term.value && depth < 10 && result.lookups <= 20) {
        const target = term.value.toLowerCase();
        result.includes.push(target);
        if (visited.has(target)) continue;
        visited.add(target);
        const sub = (await txt(target, signal)).filter((r) => r.toLowerCase().startsWith("v=spf1"));
        if (!sub.length) {
          result.voidLookups++;
          continue;
        }
        await walk(parseSpf(sub[0]), depth + 1);
      }
    }
  };
  await walk(result.parsed, 0);
  return result;
}

export const emailSecurity: ProviderDefinition = {
  id: "email-security",
  code: "EML",
  name: "Email security",
  vendor: "Native · DoH + HTTPS",
  category: "email",
  kind: "native",
  description: "MX, SPF (with lookup counting), DMARC, DKIM selector probing, MTA-STS policy, TLS-RPT and BIMI.",
  homepage: "https://www.m3aawg.org/",
  auth: { type: "none" },
  endpoint: "DoH TXT/MX lookups · HTTPS mta-sts.{domain}",
  supports: ["DOMAIN", "EMAIL"],
  cacheTtlSeconds: 15 * 60,
  timeoutMs: 15_000,
  healthCheck: { observable: "gmail.com", type: "DOMAIN" },
  async run(ctx) {
    const host = hostFor(ctx.observable, ctx.type);
    const info = hostnameInfo(host);
    const domain = host;
    const deep = ctx.mode === "DEEP" || ctx.type === "EMAIL";
    const findings: NormalizedFinding[] = [];

    const [mxResponse, spf, dmarcTxt, mtaStsTxt, tlsRptTxt, bimiTxt] = await Promise.all([
      resolve(domain, "MX", ctx.signal).catch(() => null),
      evaluateSpf(domain, ctx.signal),
      txt(`_dmarc.${domain}`, ctx.signal),
      txt(`_mta-sts.${domain}`, ctx.signal),
      txt(`_smtp._tls.${domain}`, ctx.signal),
      txt(`default._bimi.${domain}`, ctx.signal),
    ]);

    // DMARC falls back to the organisational domain for subdomains.
    let dmarcRecord = dmarcTxt.find((r) => r.toUpperCase().startsWith("V=DMARC1"));
    let dmarcInherited = false;
    if (!dmarcRecord && info.registrableDomain && info.registrableDomain !== domain) {
      const org = await txt(`_dmarc.${info.registrableDomain}`, ctx.signal);
      dmarcRecord = org.find((r) => r.toUpperCase().startsWith("V=DMARC1"));
      dmarcInherited = Boolean(dmarcRecord);
    }
    const dmarc = dmarcRecord ? parseDmarc(dmarcRecord) : null;

    const mx = (mxResponse?.answers ?? []).filter((a) => a.type === "MX").map((a) => a.data);
    const nullMx = mx.length === 1 && /^0\s+\.?$/.test(mx[0].trim());
    const receivesMail = mx.length > 0 && !nullMx;
    const mailContext = receivesMail
      ? ""
      : " The domain publishes no usable MX record; domains that never send mail should still publish \"v=spf1 -all\" and a p=reject DMARC policy so they cannot be spoofed.";

    // SPF
    if (!spf.record) {
      findings.push({
        rule: "email.spf.missing",
        severity: "MEDIUM",
        category: "email-security",
        title: "No SPF record",
        description: `${domain} does not publish an SPF policy.${mailContext}`,
        rationale: "SPF lets receivers reject mail from servers the domain has not authorised; without it, spoofed mail is harder to filter.",
        evidence: `No TXT record starting with v=spf1 at ${domain}.`,
        remediation: receivesMail ? "Publish an SPF record listing your sending services, ending in -all or ~all." : "Publish v=spf1 -all.",
      });
    } else {
      if (spf.multiple) {
        findings.push({
          rule: "email.spf.multiple",
          severity: "MEDIUM",
          category: "email-security",
          title: "Multiple SPF records",
          description: "More than one v=spf1 record is published, which is a permanent error (permerror) for receivers.",
          rationale: "RFC 7208 requires exactly one SPF record; with several, SPF evaluation fails entirely.",
          evidence: "Multiple TXT records begin with v=spf1.",
          remediation: "Merge the records into one.",
        });
      }
      if (spf.parsed?.all === "+") {
        findings.push({
          rule: "email.spf.pass-all",
          severity: "HIGH",
          category: "email-security",
          title: "SPF allows every server on the internet (+all)",
          description: "The SPF record ends in +all, authorising any host to send mail for the domain.",
          rationale: "+all defeats the purpose of SPF and makes spoofed mail pass authentication.",
          evidence: `SPF: ${spf.record}`,
          remediation: "Replace +all with -all (or ~all while testing).",
        });
      } else if (spf.parsed?.all === "?" || (!spf.parsed?.all && !spf.parsed?.redirect)) {
        findings.push({
          rule: "email.spf.neutral",
          severity: "LOW",
          category: "email-security",
          title: spf.parsed?.all === "?" ? "SPF ends in neutral ?all" : "SPF has no terminating all mechanism",
          description: "Mail from unauthorised servers receives a neutral result instead of fail or softfail.",
          rationale: "A neutral default gives receivers no guidance to reject spoofed mail.",
          evidence: `SPF: ${spf.record}`,
          remediation: "End the record with -all (or ~all).",
        });
      }
      if (spf.lookups > 10) {
        findings.push({
          rule: "email.spf.too-many-lookups",
          severity: "MEDIUM",
          category: "email-security",
          title: `SPF requires ${spf.lookups} DNS lookups (limit is 10)`,
          description: "Evaluating the SPF record, including nested includes, exceeds the RFC 7208 limit of 10 DNS-querying terms.",
          rationale: "Receivers return permerror when the limit is exceeded, so SPF silently stops protecting the domain.",
          evidence: `Includes: ${spf.includes.join(", ")}`,
          remediation: "Flatten or remove includes to stay within 10 lookups.",
        });
      }
      if (spf.voidLookups > 2) {
        findings.push({
          rule: "email.spf.void-lookups",
          severity: "LOW",
          category: "email-security",
          title: `SPF references ${spf.voidLookups} domains without SPF records`,
          description: "Several include targets return no SPF data (void lookups).",
          rationale: "RFC 7208 allows receivers to fail evaluation after two void lookups.",
          evidence: `Includes: ${spf.includes.join(", ")}`,
        });
      }
    }

    // DMARC
    if (!dmarc) {
      findings.push({
        rule: "email.dmarc.missing",
        severity: "MEDIUM",
        category: "email-security",
        title: "DMARC policy missing",
        description: `No DMARC record at _dmarc.${domain}${info.registrableDomain && info.registrableDomain !== domain ? ` or _dmarc.${info.registrableDomain}` : ""}.${mailContext}`,
        rationale: "DMARC tells receivers what to do when SPF and DKIM fail to align with the visible From domain — it is the control that actually stops exact-domain spoofing.",
        evidence: `No _dmarc TXT record returned.`,
        remediation: "Publish v=DMARC1; p=none; rua=mailto:… to start monitoring, then move to quarantine/reject.",
      });
    } else {
      if (!dmarc.valid) {
        findings.push({
          rule: "email.dmarc.invalid",
          severity: "MEDIUM",
          category: "email-security",
          title: "DMARC record is malformed",
          description: dmarc.errors.join("; "),
          rationale: "Receivers ignore invalid DMARC records, leaving the domain unprotected.",
          evidence: `DMARC: ${dmarcRecord}`,
        });
      } else if (dmarc.policy === "none") {
        findings.push({
          rule: "email.dmarc.monitor-only",
          severity: "LOW",
          category: "email-security",
          title: "DMARC is in monitoring mode (p=none)",
          description: "Failing mail is reported but still delivered.",
          rationale: "p=none is the right first step, but offers no protection against spoofing until moved to quarantine or reject.",
          evidence: `DMARC: ${dmarcRecord}`,
          remediation: "After reviewing aggregate reports, move to p=quarantine and then p=reject.",
        });
      }
      if (dmarc.valid && dmarc.policy !== "none" && dmarc.pct < 100) {
        findings.push({
          rule: "email.dmarc.partial-pct",
          severity: "INFO",
          category: "email-security",
          title: `DMARC policy applies to ${dmarc.pct}% of failing mail`,
          description: "The pct tag limits enforcement to a sample of messages.",
          evidence: `DMARC: ${dmarcRecord}`,
        });
      }
      if (dmarc.valid && !dmarc.rua.length) {
        findings.push({
          rule: "email.dmarc.no-reporting",
          severity: "INFO",
          category: "email-security",
          title: "DMARC aggregate reporting not configured",
          description: "No rua= address is published, so the domain owner receives no visibility into spoofing attempts.",
          evidence: `DMARC: ${dmarcRecord}`,
        });
      }
    }

    // MTA-STS / TLS-RPT (only meaningful when the domain receives mail)
    const mtaStsRecord = mtaStsTxt.find((r) => r.toLowerCase().startsWith("v=stsv1"));
    let policy: ReturnType<typeof parseMtaStsPolicy> | null = null;
    let policyError: string | undefined;
    if (mtaStsRecord && deep) {
      try {
        const res = await targetRequest(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { maxRedirects: 0, timeoutMs: 6000, maxBodyBytes: 64 * 1024 });
        if (res.status === 200) policy = parseMtaStsPolicy(res.body);
        else policyError = `Policy host returned HTTP ${res.status}`;
        if (res.tls && !res.tls.authorized) policyError = `Policy host certificate is not trusted (${res.tls.authorizationError})`;
      } catch (err) {
        policyError = (err as Error).message;
      }
    }
    if (receivesMail) {
      if (!mtaStsRecord) {
        findings.push({
          rule: "email.mta-sts.missing",
          severity: "LOW",
          category: "email-security",
          title: "MTA-STS not deployed",
          description: "No _mta-sts TXT record is published.",
          rationale: "Without MTA-STS, sending servers fall back to unauthenticated opportunistic TLS, which an on-path attacker can strip to read inbound mail.",
          evidence: `No v=STSv1 record at _mta-sts.${domain}.`,
        });
      } else if (policyError || (policy && policy.errors.length)) {
        findings.push({
          rule: "email.mta-sts.broken",
          severity: "MEDIUM",
          category: "email-security",
          title: "MTA-STS policy cannot be used",
          description: policyError ?? `Policy errors: ${policy!.errors.join("; ")}`,
          rationale: "Senders ignore MTA-STS when the policy file is missing, invalid or served over untrusted TLS.",
          evidence: `TXT: ${mtaStsRecord}`,
        });
      } else if (policy?.mode === "testing") {
        findings.push({
          rule: "email.mta-sts.testing",
          severity: "INFO",
          category: "email-security",
          title: "MTA-STS is in testing mode",
          description: "Senders report failures but still deliver over unverified TLS.",
          evidence: `mode: testing, max_age ${policy.maxAge}`,
        });
      }
    }
    const tlsRptRecord = tlsRptTxt.find((r) => r.toLowerCase().startsWith("v=tlsrptv1"));
    if (receivesMail && !tlsRptRecord) {
      findings.push({
        rule: "email.tls-rpt.missing",
        severity: "INFO",
        category: "email-security",
        title: "TLS-RPT reporting not configured",
        description: "No _smtp._tls record is published.",
        rationale: "TLS-RPT delivers reports of failed TLS connections to your mail servers, surfacing downgrade attacks and certificate problems.",
        evidence: `No v=TLSRPTv1 record at _smtp._tls.${domain}.`,
      });
    }
    const bimiRecord = bimiTxt.find((r) => r.toLowerCase().startsWith("v=bimi1"));
    const bimi = bimiRecord ? parseTagList(bimiRecord) : null;

    // DKIM selector probing (deep only — it is a guess, not a discovery).
    const dkim: { selector: string; keyType: string; bits: number | null; testing: boolean }[] = [];
    if (deep) {
      const results = await Promise.all(
        COMMON_DKIM_SELECTORS.map(async (selector) => {
          const records = await txt(`${selector}._domainkey.${domain}`, ctx.signal);
          const rec = records.find((r) => /(^|;)\s*p=/.test(r) || r.toLowerCase().includes("v=dkim1"));
          if (!rec) return null;
          const tags = parseTagList(rec);
          if (!tags.p) return null;
          const keyType = (tags.k ?? "rsa").toLowerCase();
          return { selector, keyType, bits: keyType === "rsa" ? estimateRsaBits(tags.p) : null, testing: (tags.t ?? "").includes("y") };
        })
      );
      dkim.push(...results.filter((r): r is NonNullable<typeof r> => r !== null));
      const weak = dkim.filter((k) => k.keyType === "rsa" && k.bits !== null && k.bits < 2048);
      if (weak.length) {
        findings.push({
          rule: "email.dkim.weak-key",
          severity: weak.some((k) => (k.bits ?? 0) < 1024) ? "MEDIUM" : "LOW",
          category: "email-security",
          title: `DKIM key shorter than 2048 bits (${weak.map((k) => `${k.selector}: ~${k.bits}`).join(", ")})`,
          description: "One or more published DKIM RSA keys are below the currently recommended 2048-bit size.",
          rationale: "RSA-1024 DKIM keys are considered factorable by well-resourced attackers; RFC 8301 requires at least 1024 and recommends 2048.",
          evidence: `Selectors: ${weak.map((k) => k.selector).join(", ")}`,
          remediation: "Rotate to 2048-bit RSA or Ed25519 keys.",
        });
      }
    }

    const relationships: NormalizedRelationship[] = (spf.includes ?? []).slice(0, 12).map((inc) => ({
      source: { type: "domain", value: domain },
      target: { type: "domain", value: inc },
      type: "spf-includes",
      evidence: "SPF include/redirect term.",
    }));

    const posture = [
      spf.record ? `SPF ${spf.parsed?.all ?? ""}all`.replace(" all", " (no all)") : "no SPF",
      dmarc ? `DMARC p=${dmarc.policy ?? "?"}` : "no DMARC",
      mtaStsRecord ? `MTA-STS${policy?.mode ? ` ${policy.mode}` : ""}` : null,
    ].filter(Boolean);

    return {
      summary: posture.join(" · "),
      listed: true,
      facts: facts(
        fact("mx", "MX", nullMx ? ["Null MX (domain accepts no mail)"] : mx, "list", true),
        fact("spf", "SPF", spf.record ?? "Not published", "code", true),
        fact("spfLookups", "SPF DNS lookups", spf.record ? `${spf.lookups} / 10` : undefined, "mono"),
        fact("dmarc", "DMARC", dmarcRecord ? `${dmarcRecord}${dmarcInherited ? " (inherited from organisational domain)" : ""}` : "Not published", "code", true),
        fact("dkim", "DKIM selectors found", deep ? (dkim.length ? dkim.map((k) => `${k.selector} (${k.keyType}${k.bits ? ` ~${k.bits}` : ""})`) : [`None of ${COMMON_DKIM_SELECTORS.length} common selectors`]) : undefined, "list"),
        fact("mtaSts", "MTA-STS", mtaStsRecord ? (policy ? `mode ${policy.mode}, max_age ${policy.maxAge}` : mtaStsRecord) : "Not published", "text"),
        fact("tlsRpt", "TLS-RPT", tlsRptRecord ?? "Not published", "code"),
        fact("bimi", "BIMI", bimiRecord ?? "Not published", "code")
      ),
      data: {
        kind: "email-security",
        domain,
        mx,
        nullMx,
        receivesMail,
        spf: { record: spf.record, all: spf.parsed?.all ?? null, terms: spf.parsed?.terms ?? [], lookups: spf.lookups, voidLookups: spf.voidLookups, includes: spf.includes, errors: spf.errors, multiple: spf.multiple },
        dmarc: dmarc ? { record: dmarcRecord, inherited: dmarcInherited, ...dmarc } : null,
        dkim: { probed: deep, selectorsChecked: deep ? COMMON_DKIM_SELECTORS.length : 0, found: dkim },
        mtaSts: { record: mtaStsRecord, policy, error: policyError },
        tlsRpt: tlsRptRecord ? { record: tlsRptRecord, ...parseTagList(tlsRptRecord) } : null,
        bimi: bimi ? { record: bimiRecord, ...bimi } : null,
      },
      findings,
      relationships,
      raw: { mx, spf: spf.record, dmarc: dmarcRecord, mtaSts: mtaStsRecord, tlsRpt: tlsRptRecord, bimi: bimiRecord, dkim },
    };
  },
};
