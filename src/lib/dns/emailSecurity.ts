import { resolveWithFallback } from "./resolve";
import type { NormalizedFinding } from "@/types/provider";

export interface EmailSecurityCheck {
  name: string;
  record?: string;
  present: boolean;
  findings: NormalizedFinding[];
}

export interface EmailSecurityReport {
  domain: string;
  spf: EmailSecurityCheck;
  dmarc: EmailSecurityCheck;
  mtaSts: EmailSecurityCheck;
  tlsRpt: EmailSecurityCheck;
  bimi: EmailSecurityCheck;
}

async function txtRecordsFor(name: string): Promise<string[]> {
  try {
    const result = await resolveWithFallback(name, "TXT");
    return result.answers.map((a) => a.data.replace(/^"|"$/g, ""));
  } catch {
    return [];
  }
}

async function checkSpf(domain: string): Promise<EmailSecurityCheck> {
  const records = await txtRecordsFor(domain);
  const spf = records.find((r) => r.toLowerCase().startsWith("v=spf1"));
  if (!spf) {
    return {
      name: "SPF",
      present: false,
      findings: [
        {
          severity: "MEDIUM",
          category: "email-security",
          title: "SPF record missing",
          description: "No SPF TXT record was found for this domain, making it easier to spoof mail claiming to be from this domain.",
          evidence: `No TXT record starting with "v=spf1" was returned for ${domain}.`,
        },
      ],
    };
  }
  const hardFail = spf.includes("-all");
  const softFail = spf.includes("~all");
  const findings: NormalizedFinding[] = [];
  if (!hardFail && !softFail) {
    findings.push({
      severity: "LOW",
      category: "email-security",
      title: "SPF record does not end in an enforcement mechanism",
      description: "The SPF record lacks a -all or ~all qualifier, weakening its enforcement.",
      evidence: `SPF record: ${spf}`,
    });
  }
  return { name: "SPF", record: spf, present: true, findings };
}

async function checkDmarc(domain: string): Promise<EmailSecurityCheck> {
  const records = await txtRecordsFor(`_dmarc.${domain}`);
  const dmarc = records.find((r) => r.toLowerCase().startsWith("v=dmarc1"));
  if (!dmarc) {
    return {
      name: "DMARC",
      present: false,
      findings: [
        {
          severity: "MEDIUM",
          category: "email-security",
          title: "DMARC policy missing",
          description: "No DMARC record was found, so receivers have no domain-owner-defined policy for handling failed SPF/DKIM checks.",
          evidence: `No _dmarc TXT record was returned for _dmarc.${domain}.`,
        },
      ],
    };
  }
  const policyMatch = dmarc.match(/p=(\w+)/i);
  const policy = policyMatch?.[1]?.toLowerCase();
  const findings: NormalizedFinding[] = [];
  if (policy === "none") {
    findings.push({
      severity: "LOW",
      category: "email-security",
      title: "DMARC policy set to monitor-only (p=none)",
      description: "The domain publishes DMARC in report-only mode, so failing mail is not rejected or quarantined.",
      evidence: `DMARC record: ${dmarc}`,
    });
  }
  return { name: "DMARC", record: dmarc, present: true, findings };
}

async function checkMtaSts(domain: string): Promise<EmailSecurityCheck> {
  const records = await txtRecordsFor(`_mta-sts.${domain}`);
  const record = records.find((r) => r.toLowerCase().startsWith("v=stsv1"));
  return {
    name: "MTA-STS",
    record,
    present: Boolean(record),
    findings: record
      ? []
      : [
          {
            severity: "LOW",
            category: "email-security",
            title: "MTA-STS not configured",
            description: "No MTA-STS policy record was found. MTA-STS helps prevent downgrade and interception attacks against inbound mail.",
            evidence: `No _mta-sts TXT record was returned for _mta-sts.${domain}.`,
          },
        ],
  };
}

async function checkTlsRpt(domain: string): Promise<EmailSecurityCheck> {
  const records = await txtRecordsFor(`_smtp._tls.${domain}`);
  const record = records.find((r) => r.toLowerCase().startsWith("v=tlsrptv1"));
  return {
    name: "TLS-RPT",
    record,
    present: Boolean(record),
    findings: record
      ? []
      : [
          {
            severity: "INFO",
            category: "email-security",
            title: "TLS-RPT not configured",
            description: "No TLS-RPT record was found, so the domain owner does not receive reports of failed opportunistic TLS connections.",
            evidence: `No _smtp._tls TXT record was returned for _smtp._tls.${domain}.`,
          },
        ],
  };
}

async function checkBimi(domain: string): Promise<EmailSecurityCheck> {
  const records = await txtRecordsFor(`default._bimi.${domain}`);
  const record = records.find((r) => r.toLowerCase().startsWith("v=bimi1"));
  return {
    name: "BIMI",
    record,
    present: Boolean(record),
    findings: [],
  };
}

export async function analyzeEmailSecurity(domain: string): Promise<EmailSecurityReport> {
  const [spf, dmarc, mtaSts, tlsRpt, bimi] = await Promise.all([
    checkSpf(domain),
    checkDmarc(domain),
    checkMtaSts(domain),
    checkTlsRpt(domain),
    checkBimi(domain),
  ]);
  return { domain, spf, dmarc, mtaSts, tlsRpt, bimi };
}
