import "server-only";
import type { InvestigationMode, ObservableType, PlanStep, ProviderOutcome } from "@/lib/core/types";
import { getProvider, planSkipReason } from "@/lib/providers/registry";
import { executeProvider, type RuntimeServices } from "@/lib/providers/runtime";

export interface StepContext {
  observable: string;
  type: ObservableType;
  mode: InvestigationMode;
  fresh?: boolean;
  signal?: AbortSignal;
  services: RuntimeServices;
}

/** Runs one plan step: policy skips first, then the provider itself. Never throws. */
export function stepRunner(ctx: StepContext) {
  return async (step: PlanStep, dependencies: Map<string, ProviderOutcome>): Promise<ProviderOutcome> => {
    const now = new Date().toISOString();
    const def = getProvider(step.id);
    if (!def) return { provider: step.id, status: "UNAVAILABLE", latencyMs: 0, retrievedAt: now, errorType: "unknown-provider", errorMessage: "This source is no longer available." };
    const reason = planSkipReason(def, ctx.observable, ctx.type);
    if (reason) return { provider: step.id, status: "SKIPPED", latencyMs: 0, retrievedAt: now, errorType: "not-applicable", errorMessage: reason };
    return executeProvider(def, { observable: ctx.observable, type: ctx.type, mode: ctx.mode, fresh: ctx.fresh, signal: ctx.signal, dependencies }, { ...ctx.services, catalog: ctx.services.catalog ?? getProvider });
  };
}
