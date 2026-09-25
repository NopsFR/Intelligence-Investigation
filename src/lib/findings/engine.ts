import type { Finding } from "@/types/finding";
import type { ProviderOutcome } from "@/types/provider";
import { SEVERITY_ORDER } from "@/types/finding";

let counter = 0;
function nextId(): string {
  counter += 1;
  return `finding-${Date.now()}-${counter}`;
}

/**
 * Collects the findings each provider already emitted (evidence-based, tied
 * to that provider's own data) into the flat list the UI renders. This does
 * not invent new findings — it only aggregates and sorts what providers
 * already reported, each retaining its own source.
 */
export function collectFindings(outcomes: ProviderOutcome[]): Finding[] {
  const findings: Finding[] = [];

  for (const outcome of outcomes) {
    const normalizedFindings = outcome.normalized?.findings ?? [];
    for (const f of normalizedFindings) {
      findings.push({
        id: nextId(),
        severity: f.severity,
        category: f.category,
        title: f.title,
        description: f.description,
        evidence: f.evidence,
        source: outcome.provider,
        observedAt: outcome.retrievedAt,
        confidence: f.confidence,
      });
    }
  }

  return findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

export function addExternalFindings(
  findings: Finding[],
  source: string,
  extra: { severity: Finding["severity"]; category: string; title: string; description: string; evidence: string }[]
): Finding[] {
  const observedAt = new Date().toISOString();
  const additional: Finding[] = extra.map((f) => ({
    id: nextId(),
    ...f,
    source,
    observedAt,
  }));
  return [...findings, ...additional].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
