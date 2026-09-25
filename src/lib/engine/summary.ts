import "server-only";
import { ANSWERED_STATUSES, NEUTRAL_STATUSES, SEVERITY_RANK, type InvestigationStatus, type ProviderOutcome, type Severity } from "@/lib/core/types";
import { getProvider } from "@/lib/providers/registry";

/** Sources are analysers that gather evidence; derived steps only combine it. */
function sources(outcomes: ProviderOutcome[]): ProviderOutcome[] {
  return outcomes.filter((o) => getProvider(o.provider)?.kind !== "derived");
}

export function summarize(outcomes: ProviderOutcome[]): string {
  const findings = outcomes.flatMap((o) => o.result?.findings ?? []);
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const severityText = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[])
    .filter((s) => counts.get(s))
    .map((s) => `${counts.get(s)} ${s.toLowerCase()}`)
    .join(", ");
  // The correlation verdict leads the summary when intelligence sources actually answered.
  const correlation = outcomes.find((o) => o.provider === "correlation")?.result;
  const data = correlation?.data as { adverse?: unknown[]; silent?: unknown[] } | undefined;
  const assessment = data && ((data.adverse?.length ?? 0) > 0 || (data.silent?.length ?? 0) > 0) ? correlation?.summary : undefined;
  const own = sources(outcomes);
  const answered = own.filter((o) => ANSWERED_STATUSES.has(o.status)).length;
  const findingText = severityText ? `${severityText} finding${findings.length === 1 ? "" : "s"}` : findings.length ? "Informational findings only" : "No findings";
  return [assessment, findingText, `${answered}/${own.length} sources answered`].filter(Boolean).join(" · ");
}

export function finalStatus(outcomes: ProviderOutcome[]): InvestigationStatus {
  const own = sources(outcomes);
  const answered = own.filter((o) => ANSWERED_STATUSES.has(o.status)).length;
  const failed = own.filter((o) => !ANSWERED_STATUSES.has(o.status) && !NEUTRAL_STATUSES.has(o.status)).length;
  if (!answered) return "FAILED";
  return failed ? "PARTIAL" : "COMPLETE";
}

export function highestSeverity(outcomes: ProviderOutcome[]): Severity | null {
  return outcomes
    .flatMap((o) => o.result?.findings ?? [])
    .reduce<Severity | null>((w, f) => (!w || SEVERITY_RANK[f.severity] < SEVERITY_RANK[w] ? f.severity : w), null);
}
