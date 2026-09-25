import "server-only";
import type { Prisma } from "@prisma/client";
import type { InvestigationMode, ObservableType, PlanStep, ProviderOutcome } from "@/lib/core/types";
import { prisma } from "@/lib/db/client";
import { cacheStore, quotaStore } from "@/lib/db/stores";
import { STALE_AFTER_MS } from "@/lib/db/investigations";
import { log } from "@/lib/server/log";
import { buildPlan, getProvider } from "@/lib/providers/registry";
import type { RuntimeServices } from "@/lib/providers/runtime";
import { executePlan } from "./plan-runner";
import { stepRunner } from "./step";
import { finalStatus, highestSeverity, summarize } from "./summary";

/** Steps running at once. External APIs are few per observable; this mostly bounds sockets. */
const CONCURRENCY = 8;
/** Hard ceiling for one investigation, kept under the route's maxDuration. */
const DEADLINE_MS: Record<InvestigationMode, number> = { QUICK: 45_000, DEEP: 100_000 };

export const services: RuntimeServices = {
  cache: cacheStore,
  quota: quotaStore,
  catalog: getProvider,
  logger: (message, meta) => log("warn", message, meta),
};

export interface StartInput {
  observable: string;
  normalized: string;
  type: ObservableType;
  mode: InvestigationMode;
  /** Bypass provider caches. */
  fresh?: boolean;
}

/**
 * Creates the investigation row (RUNNING, with its plan) and returns its id.
 * An identical investigation already in flight is reused instead of started twice.
 */
export async function createInvestigation(input: StartInput): Promise<{ id: string; reused: boolean }> {
  const inflight = await prisma.investigation.findFirst({
    where: { normalizedObservable: input.normalized, observableType: input.type, mode: input.mode, status: "RUNNING", updatedAt: { gt: new Date(Date.now() - STALE_AFTER_MS) } },
    orderBy: { createdAt: "desc" },
    select: { id: true },
  });
  if (inflight && !input.fresh) return { id: inflight.id, reused: true };

  const previous = await prisma.investigation.findFirst({
    where: { normalizedObservable: input.normalized, observableType: input.type, status: { in: ["COMPLETE", "PARTIAL"] } },
    orderBy: { createdAt: "desc" },
    select: { id: true },
  });
  const plan = buildPlan(input.type, input.mode);
  const created = await prisma.investigation.create({
    data: {
      observable: input.observable,
      normalizedObservable: input.normalized,
      observableType: input.type,
      mode: input.mode,
      status: "RUNNING",
      plan: plan as unknown as Prisma.InputJsonValue,
      metadata: { fresh: Boolean(input.fresh) },
      previousId: previous?.id,
    },
    select: { id: true },
  });
  await prisma.observable
    .upsert({ where: { value_type: { value: input.normalized, type: input.type } }, create: { value: input.normalized, type: input.type }, update: {} })
    .catch(() => undefined);
  return { id: created.id, reused: false };
}

async function persistOutcome(investigationId: string, outcome: ProviderOutcome) {
  const result = outcome.result;
  const observedAt = new Date(outcome.retrievedAt);
  const data = {
    status: outcome.status,
    latencyMs: Math.round(outcome.latencyMs),
    startedAt: outcome.startedAt ? new Date(outcome.startedAt) : null,
    retrievedAt: observedAt,
    cached: Boolean(outcome.cached),
    httpStatus: outcome.httpStatus ?? null,
    errorType: outcome.errorType ?? null,
    errorMessage: outcome.errorMessage ?? null,
    result: (result ?? undefined) as Prisma.InputJsonValue | undefined,
    raw: (outcome.raw ?? undefined) as Prisma.InputJsonValue | undefined,
    diagnostics: (outcome.diagnostics ?? undefined) as Prisma.InputJsonValue | undefined,
  };
  await prisma.$transaction([
    prisma.providerResult.upsert({
      where: { investigationId_provider: { investigationId, provider: outcome.provider } },
      create: { investigationId, provider: outcome.provider, ...data },
      update: data,
    }),
    prisma.finding.deleteMany({ where: { investigationId, source: outcome.provider } }),
    prisma.relationship.deleteMany({ where: { investigationId, provider: outcome.provider } }),
    prisma.finding.createMany({
      data: (result?.findings ?? []).map((f) => ({
        investigationId,
        rule: f.rule,
        severity: f.severity,
        category: f.category,
        title: f.title.slice(0, 500),
        description: f.description,
        rationale: f.rationale ?? null,
        evidence: f.evidence,
        evidenceData: (f.evidenceData ?? undefined) as Prisma.InputJsonValue | undefined,
        source: outcome.provider,
        observable: f.observable ?? null,
        confidence: f.confidence ?? null,
        remediation: f.remediation ?? null,
        references: (f.references ?? undefined) as Prisma.InputJsonValue | undefined,
        observedAt,
      })),
    }),
    prisma.relationship.createMany({
      data: (result?.relationships ?? []).slice(0, 400).map((r) => ({
        investigationId,
        sourceType: r.source.type,
        sourceValue: r.source.value,
        targetType: r.target.type,
        targetValue: r.target.value,
        targetLabel: r.target.label ?? null,
        relationType: r.type,
        provider: outcome.provider,
        evidence: r.evidence,
        observedAt,
      })),
    }),
    // Touch the parent so pollers and stale detection see progress.
    prisma.investigation.update({ where: { id: investigationId }, data: { updatedAt: new Date() } }),
  ]);
}

/**
 * Executes an investigation's plan: dependency-ordered, bounded concurrency,
 * each outcome persisted as soon as it lands so the UI can stream progress.
 */
export async function runInvestigation(id: string): Promise<void> {
  const inv = await prisma.investigation.findUnique({ where: { id } });
  if (!inv || inv.status !== "RUNNING") return;
  const type = inv.observableType as ObservableType;
  const mode = inv.mode as InvestigationMode;
  const plan = (inv.plan as unknown as PlanStep[]) ?? [];
  const fresh = Boolean((inv.metadata as { fresh?: boolean } | null)?.fresh);
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(new Error("Investigation deadline reached")), DEADLINE_MS[mode]);

  let outcomes = new Map<string, ProviderOutcome>();
  try {
    outcomes = await executePlan(plan, stepRunner({ observable: inv.normalizedObservable, type, mode, fresh, signal: controller.signal, services }), {
      concurrency: CONCURRENCY,
      onOutcome: async (outcome) => {
        try {
          await persistOutcome(id, outcome);
        } catch (err) {
          log("error", "persist outcome failed", { investigation: id, provider: outcome.provider, error: (err as Error).message });
        }
      },
    });
  } finally {
    clearTimeout(deadline);
  }

  const all = plan.map((s) => outcomes.get(s.id)).filter((o): o is ProviderOutcome => Boolean(o));
  await prisma.investigation.update({
    where: { id },
    data: {
      status: finalStatus(all),
      completedAt: new Date(),
      durationMs: Date.now() - inv.createdAt.getTime(),
      summary: summarize(all),
      metadata: { fresh, highestSeverity: highestSeverity(all), cachedSources: all.filter((o) => o.cached).map((o) => o.provider) },
    },
  });
}
