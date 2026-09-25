"use client";

import { useEffect, useRef, useState } from "react";
import {
  ANSWERED_STATUSES,
  NEUTRAL_STATUSES,
  SEVERITY_RANK,
  type FindingRecord,
  type InvestigationRecord,
  type ProviderOutcome,
  type Severity,
  type TaskState,
} from "@/lib/core/types";

/** Mirrors the engine's scheduler (plan order, dependencies satisfied, 8 slots) to show which steps are executing. */
const ENGINE_CONCURRENCY = 8;

export interface StepView {
  id: string;
  state: TaskState;
  outcome?: ProviderOutcome;
  dependsOn: string[];
}

export function stepViews(inv: InvestigationRecord): StepView[] {
  const byId = new Map(inv.providerResults.map((o) => [o.provider, o]));
  const planned = new Set(inv.plan.map((s) => s.id));
  let slots = ENGINE_CONCURRENCY;
  const steps: StepView[] = inv.plan.map((s) => {
    const outcome = byId.get(s.id);
    if (outcome) return { id: s.id, state: outcome.status, outcome, dependsOn: s.dependsOn ?? [] };
    const ready = (s.dependsOn ?? []).every((d) => byId.has(d) || !planned.has(d));
    if (inv.status === "RUNNING" && ready && slots > 0) {
      slots--;
      return { id: s.id, state: "RUNNING", dependsOn: s.dependsOn ?? [] };
    }
    return { id: s.id, state: "QUEUED", dependsOn: s.dependsOn ?? [] };
  });
  // Results for steps no longer in the plan (older investigations) still deserve a row.
  for (const o of inv.providerResults) if (!planned.has(o.provider)) steps.push({ id: o.provider, state: o.status, outcome: o, dependsOn: [] });
  return steps;
}

/**
 * Progress over the plan. Counts of answered/failed cover evidence sources only;
 * derived analysers (correlation, mapping) are excluded via `isDerived`.
 */
export function progressOf(inv: InvestigationRecord, isDerived: (id: string) => boolean = () => false) {
  const steps = stepViews(inv);
  const sources = steps.filter((s) => !isDerived(s.id));
  const done = steps.filter((s) => s.outcome).length;
  const answered = sources.filter((s) => s.outcome && ANSWERED_STATUSES.has(s.outcome.status)).length;
  const neutral = sources.filter((s) => s.outcome && NEUTRAL_STATUSES.has(s.outcome.status)).length;
  const failedSteps = sources.filter((s) => s.outcome && !ANSWERED_STATUSES.has(s.outcome.status) && !NEUTRAL_STATUSES.has(s.outcome.status));
  return { steps, total: steps.length, done, sources: sources.length, answered, failed: failedSteps.length, failedSteps, neutral, running: steps.filter((s) => s.state === "RUNNING").length };
}

export function sortFindings(findings: FindingRecord[]): FindingRecord[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.title.localeCompare(b.title));
}

export function severityCounts(findings: FindingRecord[]): Record<Severity, number> {
  const c: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

export function outcomeData<T extends { kind: string }>(inv: InvestigationRecord, provider: string): T | undefined {
  return inv.providerResults.find((o) => o.provider === provider)?.result?.data as T | undefined;
}

/**
 * Polls the investigation while it runs. Backs off gently, pauses when the tab
 * is hidden, and stops as soon as the record is final.
 */
export function useLiveInvestigation(initial: InvestigationRecord): { inv: InvestigationRecord; error: string | null; refresh: () => void } {
  const [inv, setInv] = useState(initial);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const delay = useRef(900);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- server navigation delivered a new record
    setInv(initial);
    delay.current = 900;
  }, [initial]);

  useEffect(() => {
    if (inv.status !== "RUNNING" && nonce === 0) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      if (document.visibilityState === "hidden") {
        timer = setTimeout(tick, 1500);
        return;
      }
      try {
        const res = await fetch(`/api/investigations/${inv.id}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const next = ((await res.json()) as { investigation: InvestigationRecord }).investigation;
        if (!alive) return;
        setError(null);
        setInv(next);
        if (next.status === "RUNNING") {
          delay.current = Math.min(2500, delay.current + 150);
          timer = setTimeout(tick, delay.current);
        }
      } catch (err) {
        if (!alive) return;
        setError((err as Error).message);
        timer = setTimeout(tick, 4000);
      }
    };
    timer = setTimeout(tick, nonce ? 0 : delay.current);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- restart only on id/status/nonce changes
  }, [inv.id, inv.status === "RUNNING", nonce]);

  return { inv, error, refresh: () => setNonce((n) => n + 1) };
}

export function useElapsed(startIso: string, running: boolean, finalMs?: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setNow(Date.now()), 100);
    return () => clearInterval(t);
  }, [running]);
  if (!running && finalMs !== undefined) return finalMs;
  return Math.max(0, now - new Date(startIso).getTime());
}
