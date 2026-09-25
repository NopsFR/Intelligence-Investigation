import "server-only";
import type { ObservableType, Severity } from "@/lib/core/types";
import { PROVIDERS } from "@/lib/providers/registry";
import { isConfigured } from "@/lib/providers/runtime";
import { prisma } from "./client";
import { connectionState, type ConnectionState } from "./health";
import { listInvestigations } from "./investigations";

export interface DashboardData {
  generatedAt: string;
  totals: { investigations: number; last7d: number; running: number; iocs: number; observables: number };
  activity: { day: string; count: number }[];
  severity30d: Record<Severity, number>;
  byType: { type: ObservableType; count: number }[];
  attention: { id: string; severity: Severity; title: string; source: string; observedAt: string; investigationId: string; observable: string }[];
  recurring: { value: string; type: ObservableType; count: number; lastId: string; lastAt: string }[];
  recent: Awaited<ReturnType<typeof listInvestigations>>["items"];
  sources: { total: number; external: number; configured: number; states: Partial<Record<ConnectionState, number>>; lastCheckedAt?: string };
}

export async function dashboardData(): Promise<DashboardData> {
  const now = Date.now();
  const d7 = new Date(now - 7 * 86400_000);
  const d14 = new Date(now - 13 * 86400_000);
  d14.setUTCHours(0, 0, 0, 0);
  const d30 = new Date(now - 30 * 86400_000);

  const [total, last7d, running, iocs, observables, activityRows, severityRows, typeRows, attentionRows, recurringRows, recent, health] = await Promise.all([
    prisma.investigation.count(),
    prisma.investigation.count({ where: { createdAt: { gt: d7 } } }),
    prisma.investigation.count({ where: { status: "RUNNING" } }),
    prisma.iocEntry.count(),
    prisma.observable.count(),
    prisma.$queryRaw<{ day: Date; count: bigint }[]>`
      SELECT date_trunc('day', "createdAt") AS day, COUNT(*)::bigint AS count
      FROM "Investigation" WHERE "createdAt" >= ${d14} GROUP BY 1 ORDER BY 1`,
    prisma.finding.groupBy({ by: ["severity"], where: { observedAt: { gt: d30 } }, _count: { _all: true } }),
    prisma.investigation.groupBy({ by: ["observableType"], _count: { _all: true } }),
    prisma.finding.findMany({
      where: { severity: { in: ["CRITICAL", "HIGH"] }, observedAt: { gt: d30 } },
      orderBy: [{ observedAt: "desc" }],
      take: 40,
      select: { id: true, severity: true, title: true, source: true, observedAt: true, investigationId: true, investigation: { select: { normalizedObservable: true } } },
    }),
    prisma.investigation.groupBy({ by: ["normalizedObservable", "observableType"], _count: { _all: true }, _max: { createdAt: true }, having: { normalizedObservable: { _count: { gt: 1 } } }, orderBy: { _count: { normalizedObservable: "desc" } }, take: 6 }),
    listInvestigations({ limit: 8 }),
    prisma.apiProviderHealth.findMany(),
  ]);

  const activity: DashboardData["activity"] = [];
  for (let i = 0; i < 14; i++) {
    const day = new Date(d14.getTime() + i * 86400_000);
    const key = day.toISOString().slice(0, 10);
    const row = activityRows.find((r) => new Date(r.day).toISOString().slice(0, 10) === key);
    activity.push({ day: key, count: row ? Number(row.count) : 0 });
  }

  const severity30d: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const r of severityRows) if (r.severity in severity30d) severity30d[r.severity as Severity] = r._count._all;

  // Newest high-impact finding per investigation, so one noisy case does not fill the list.
  const seen = new Set<string>();
  const attention = attentionRows
    .filter((f) => (seen.has(f.investigationId) ? false : (seen.add(f.investigationId), true)))
    .slice(0, 8)
    .map((f) => ({ id: f.id, severity: f.severity as Severity, title: f.title, source: f.source, observedAt: f.observedAt.toISOString(), investigationId: f.investigationId, observable: f.investigation.normalizedObservable }));

  const recurring = await Promise.all(
    recurringRows.map(async (r) => {
      const last = await prisma.investigation.findFirst({ where: { normalizedObservable: r.normalizedObservable, observableType: r.observableType }, orderBy: { createdAt: "desc" }, select: { id: true, createdAt: true } });
      return { value: r.normalizedObservable, type: r.observableType as ObservableType, count: r._count._all, lastId: last?.id ?? "", lastAt: (last?.createdAt ?? r._max.createdAt ?? new Date()).toISOString() };
    })
  );

  const external = PROVIDERS.filter((p) => p.kind === "external");
  const healthBy = new Map(health.map((h) => [h.provider, h]));
  const states: Partial<Record<ConnectionState, number>> = {};
  for (const p of external) {
    const state = !isConfigured(p) ? "NOT_CONFIGURED" : connectionState(healthBy.get(p.id)?.lastStatus);
    states[state] = (states[state] ?? 0) + 1;
  }
  const lastChecked = health.reduce<Date | null>((l, h) => (h.lastCheckedAt && (!l || h.lastCheckedAt > l) ? h.lastCheckedAt : l), null);

  return {
    generatedAt: new Date().toISOString(),
    totals: { investigations: total, last7d, running, iocs, observables },
    activity,
    severity30d,
    byType: typeRows.map((r) => ({ type: r.observableType as ObservableType, count: r._count._all })).sort((a, b) => b.count - a.count),
    attention,
    recurring,
    recent: recent.items,
    sources: { total: PROVIDERS.length, external: external.length, configured: external.filter((p) => isConfigured(p)).length, states, lastCheckedAt: lastChecked?.toISOString() },
  };
}
