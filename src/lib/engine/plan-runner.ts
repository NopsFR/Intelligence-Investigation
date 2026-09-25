import type { PlanStep, ProviderOutcome } from "@/lib/core/types";

/**
 * Executes a dependency-ordered plan with bounded concurrency. Each step
 * receives the outcomes of the steps it depends on. Pure orchestration: the
 * caller decides how a step runs and what happens with its outcome.
 */
export async function executePlan(
  plan: PlanStep[],
  runStep: (step: PlanStep, dependencies: Map<string, ProviderOutcome>) => Promise<ProviderOutcome>,
  options: { concurrency?: number; onOutcome?: (outcome: ProviderOutcome) => Promise<void> | void } = {}
): Promise<Map<string, ProviderOutcome>> {
  const concurrency = options.concurrency ?? 8;
  const planned = new Set(plan.map((s) => s.id));
  const outcomes = new Map<string, ProviderOutcome>();
  const pending = new Map(plan.map((s) => [s.id, s]));
  const running = new Map<string, Promise<void>>();

  const launch = (step: PlanStep) => {
    pending.delete(step.id);
    const deps = new Map<string, ProviderOutcome>();
    for (const d of step.dependsOn ?? []) {
      const o = outcomes.get(d);
      if (o) deps.set(d, o);
    }
    const task = (async () => {
      const outcome = await runStep(step, deps);
      outcomes.set(step.id, outcome);
      await options.onOutcome?.(outcome);
    })().finally(() => running.delete(step.id));
    running.set(step.id, task);
  };

  while (pending.size || running.size) {
    for (const step of [...pending.values()]) {
      if (running.size >= concurrency) break;
      if ((step.dependsOn ?? []).every((d) => outcomes.has(d) || !planned.has(d))) launch(step);
    }
    if (!running.size) {
      // Unsatisfiable dependencies (a cycle): run what is left without them.
      for (const step of [...pending.values()]) launch(step);
      continue;
    }
    await Promise.race(running.values());
  }
  return outcomes;
}
