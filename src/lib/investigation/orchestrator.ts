import { detectObservable } from "@/lib/observables/detect";
import { providersFor } from "@/lib/providers/registry";
import { analyzeEmailSecurity } from "@/lib/dns/emailSecurity";
import { inspectTls, findingsForCertificate, TlsInspectionError } from "@/lib/tls/inspect";
import { inspectSecurityHeaders, findingsForHeaders } from "@/lib/headers/inspect";
import { parseUrl } from "@/lib/observables/url";
import { collectFindings, addExternalFindings } from "@/lib/findings/engine";
import { buildRelationships } from "@/lib/correlation/engine";
import type { ObservableType } from "@/types/observable";
import type { InvestigationMode, InvestigationStatus, RelationshipRecord } from "@/types/investigation";
import type { Finding } from "@/types/finding";
import type { NormalizedFinding, ProviderOutcome } from "@/types/provider";

export interface OrchestratedInvestigation {
  observable: string;
  observableType: ObservableType;
  normalizedObservable: string;
  mode: InvestigationMode;
  status: InvestigationStatus;
  summary: string;
  providerResults: ProviderOutcome[];
  findings: Finding[];
  relationships: RelationshipRecord[];
}

export class UnrecognizedObservableError extends Error {
  constructor() {
    super("Could not detect a supported observable type for this input.");
    this.name = "UnrecognizedObservableError";
  }
}

function nativeOutcome(
  provider: string,
  latencyMs: number,
  summary: string,
  fields: Record<string, unknown>,
  findings: NormalizedFinding[] = []
): ProviderOutcome {
  return {
    provider,
    status: "SUCCESS",
    latencyMs,
    retrievedAt: new Date().toISOString(),
    normalized: { summary, fields, findings },
  };
}

function nativeFailure(provider: string, latencyMs: number, message: string): ProviderOutcome {
  return {
    provider,
    status: "UNAVAILABLE",
    latencyMs,
    retrievedAt: new Date().toISOString(),
    errorType: "unavailable",
    errorMessage: message,
  };
}

async function runNativeEmailSecurity(domain: string): Promise<ProviderOutcome> {
  const start = Date.now();
  try {
    const report = await analyzeEmailSecurity(domain);
    const allFindings = [
      ...report.spf.findings,
      ...report.dmarc.findings,
      ...report.mtaSts.findings,
      ...report.tlsRpt.findings,
      ...report.bimi.findings,
    ];
    return nativeOutcome(
      "email-security",
      Date.now() - start,
      `${allFindings.length} email security observation(s)`,
      {
        spf: report.spf.record ?? "Not present",
        dmarc: report.dmarc.record ?? "Not present",
        mtaSts: report.mtaSts.record ?? "Not present",
        tlsRpt: report.tlsRpt.record ?? "Not present",
        bimi: report.bimi.record ?? "Not present",
      },
      allFindings
    );
  } catch (err) {
    return nativeFailure("email-security", Date.now() - start, err instanceof Error ? err.message : "Email security analysis failed");
  }
}

async function runNativeTls(hostname: string): Promise<ProviderOutcome> {
  const start = Date.now();
  try {
    const cert = await inspectTls(hostname);
    const findings = findingsForCertificate(hostname, cert);
    return nativeOutcome(
      "tls-inspection",
      Date.now() - start,
      `${cert.protocol ?? "TLS"} — expires in ${cert.daysUntilExpiry} day(s)`,
      {
        subject: cert.subject,
        issuer: cert.issuer,
        subjectAltNames: cert.subjectAltNames,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        daysUntilExpiry: cert.daysUntilExpiry,
        serialNumber: cert.serialNumber,
        fingerprint256: cert.fingerprint256,
        protocol: cert.protocol,
        cipher: cert.cipher,
      },
      findings
    );
  } catch (err) {
    const message = err instanceof TlsInspectionError ? err.message : "TLS inspection failed";
    return nativeFailure("tls-inspection", Date.now() - start, message);
  }
}

async function runNativeHeaders(url: string, hostname: string): Promise<ProviderOutcome> {
  const start = Date.now();
  const result = await inspectSecurityHeaders(url);
  if (!result.reachable) {
    return nativeFailure("security-headers", Date.now() - start, result.error ?? "Unable to retrieve headers");
  }
  const findings = findingsForHeaders(hostname, result);
  return nativeOutcome(
    "security-headers",
    Date.now() - start,
    `${Object.values(result.headers).filter(Boolean).length}/${Object.keys(result.headers).length} security headers present`,
    { ...result.headers },
    findings
  );
}

async function runNativeUrlParser(rawUrl: string): Promise<ProviderOutcome> {
  const start = Date.now();
  const parsed = parseUrl(rawUrl);
  if (!parsed) {
    return nativeFailure("url-parser", Date.now() - start, "Could not parse URL structure");
  }
  return nativeOutcome("url-parser", Date.now() - start, `${parsed.protocol}://${parsed.hostname}${parsed.pathname}`, { ...parsed });
}

function computeStatus(outcomes: ProviderOutcome[]): InvestigationStatus {
  if (outcomes.length === 0) return "FAILED";
  const succeeded = outcomes.filter((o) => o.status === "SUCCESS" || o.status === "PARTIAL" || o.status === "EMPTY").length;
  if (succeeded === 0) return "FAILED";
  if (succeeded === outcomes.length) return "COMPLETE";
  return "PARTIAL";
}

function summarize(observable: string, status: InvestigationStatus, outcomes: ProviderOutcome[]): string {
  const succeeded = outcomes.filter((o) => o.status === "SUCCESS" || o.status === "PARTIAL" || o.status === "EMPTY").length;
  if (status === "FAILED") return `No providers returned data for ${observable}.`;
  if (status === "PARTIAL") return `Partial investigation — ${succeeded}/${outcomes.length} sources returned data.`;
  return `Investigation complete — all ${outcomes.length} sources returned data.`;
}

export async function runInvestigation(rawObservable: string, mode: InvestigationMode): Promise<OrchestratedInvestigation> {
  const detected = detectObservable(rawObservable);
  if (!detected) throw new UnrecognizedObservableError();

  const providers = providersFor(detected.type, mode);
  const signal = AbortSignal.timeout(30000);

  const providerOutcomes = await Promise.all(
    providers.map((p) =>
      p.isConfigured()
        ? p.investigate({ observable: detected.normalized, type: detected.type, signal })
        : Promise.resolve({
            provider: p.meta.id,
            status: "NOT_CONFIGURED" as const,
            latencyMs: 0,
            retrievedAt: new Date().toISOString(),
            errorMessage: `Add the required API key to enable ${p.meta.name}.`,
          })
    )
  );

  const nativeOutcomes: ProviderOutcome[] = [];
  const isDeep = mode === "DEEP";

  if (detected.type === "DOMAIN") {
    nativeOutcomes.push(await runNativeEmailSecurity(detected.normalized));
    if (isDeep) {
      nativeOutcomes.push(await runNativeTls(detected.normalized));
      nativeOutcomes.push(await runNativeHeaders(`https://${detected.normalized}`, detected.normalized));
    }
  } else if (detected.type === "URL") {
    const parsed = parseUrl(detected.normalized);
    nativeOutcomes.push(await runNativeUrlParser(detected.normalized));
    if (parsed && !parsed.isIp) {
      nativeOutcomes.push(await runNativeTls(parsed.hostname));
      nativeOutcomes.push(await runNativeHeaders(detected.normalized, parsed.hostname));
    }
  }

  const allOutcomes = [...providerOutcomes, ...nativeOutcomes];
  const status = computeStatus(allOutcomes);
  const findings = collectFindings(allOutcomes);
  const relationships = buildRelationships(detected.normalized, allOutcomes);

  return {
    observable: rawObservable,
    observableType: detected.type,
    normalizedObservable: detected.normalized,
    mode,
    status,
    summary: summarize(detected.normalized, status, allOutcomes),
    providerResults: allOutcomes,
    findings,
    relationships,
  };
}

export { addExternalFindings };
