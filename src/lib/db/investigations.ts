import { prisma } from "./client";
import type { OrchestratedInvestigation } from "@/lib/investigation/orchestrator";
import type { Investigation } from "@/types/investigation";
import type { ProviderOutcome } from "@/types/provider";
import type { Finding } from "@/types/finding";
import type { Prisma } from "@prisma/client";

function sanitizeRaw(raw: unknown): string | null {
  if (raw === undefined || raw === null) return null;
  try {
    // Strip anything that looks like a credential before persisting.
    const json = JSON.stringify(raw, (key, value) => {
      if (/key|token|auth|secret|password|cookie/i.test(key)) return "[redacted]";
      return value;
    });
    return json.length > 200_000 ? json.slice(0, 200_000) : json;
  } catch {
    return null;
  }
}

export async function saveInvestigation(result: OrchestratedInvestigation): Promise<Investigation> {
  const created = await prisma.investigation.create({
    data: {
      observable: result.observable,
      observableType: result.observableType,
      normalizedObservable: result.normalizedObservable,
      mode: result.mode,
      status: result.status,
      summary: result.summary,
      providerResults: {
        create: result.providerResults.map((r) => ({
          provider: r.provider,
          status: r.status,
          latencyMs: r.latencyMs,
          retrievedAt: new Date(r.retrievedAt),
          errorType: r.errorType,
          errorMessage: r.errorMessage,
          normalized: r.normalized ? JSON.stringify(r.normalized) : null,
          raw: sanitizeRaw(r.raw),
        })),
      },
      findings: {
        create: result.findings.map((f) => ({
          severity: f.severity,
          category: f.category,
          title: f.title,
          description: f.description,
          evidence: f.evidence,
          source: f.source,
          observedAt: new Date(f.observedAt),
          confidence: f.confidence,
          methodology: f.methodology,
        })),
      },
      relationships: {
        create: result.relationships.map((r) => ({
          sourceNode: r.sourceNode,
          targetNode: r.targetNode,
          relationType: r.relationType,
          sourceProvider: r.sourceProvider,
          evidence: r.evidence,
          observedAt: new Date(r.observedAt),
        })),
      },
    },
    include: { providerResults: true, findings: true, relationships: true },
  });

  await upsertObservable(result.normalizedObservable, result.observableType);

  return toInvestigation(created);
}

async function upsertObservable(value: string, type: OrchestratedInvestigation["observableType"]) {
  await prisma.observable.upsert({
    where: { value_type: { value, type } },
    create: { value, type },
    update: {},
  });
}

type InvestigationWithRelations = Prisma.InvestigationGetPayload<{
  include: { providerResults: true; findings: true; relationships: true };
}>;

function toInvestigation(record: InvestigationWithRelations): Investigation {
  return {
    id: record.id,
    createdAt: record.createdAt.toISOString(),
    updatedAt: record.updatedAt.toISOString(),
    observable: record.observable,
    observableType: record.observableType,
    normalizedObservable: record.normalizedObservable,
    mode: record.mode,
    status: record.status,
    summary: record.summary ?? "",
    providerResults: record.providerResults.map(
      (r): ProviderOutcome => ({
        provider: r.provider,
        status: r.status,
        latencyMs: r.latencyMs ?? 0,
        retrievedAt: r.retrievedAt.toISOString(),
        errorType: r.errorType ?? undefined,
        errorMessage: r.errorMessage ?? undefined,
        normalized: r.normalized ? JSON.parse(r.normalized) : undefined,
        raw: r.raw ? JSON.parse(r.raw) : undefined,
      })
    ),
    findings: record.findings.map(
      (f): Finding => ({
        id: f.id,
        severity: f.severity as Finding["severity"],
        category: f.category,
        title: f.title,
        description: f.description,
        evidence: f.evidence,
        source: f.source,
        observedAt: f.observedAt.toISOString(),
        confidence: f.confidence ?? undefined,
        methodology: f.methodology ?? undefined,
      })
    ),
    relationships: record.relationships.map((r) => ({
      id: r.id,
      sourceNode: r.sourceNode,
      targetNode: r.targetNode,
      relationType: r.relationType,
      sourceProvider: r.sourceProvider,
      evidence: r.evidence,
      observedAt: r.observedAt.toISOString(),
    })),
  };
}

export async function getInvestigation(id: string): Promise<Investigation | null> {
  const record = await prisma.investigation.findUnique({
    where: { id },
    include: { providerResults: true, findings: true, relationships: true },
  });
  return record ? toInvestigation(record) : null;
}

export interface ListInvestigationsOptions {
  limit?: number;
  offset?: number;
  observableType?: string;
  search?: string;
}

export async function listInvestigations(options: ListInvestigationsOptions = {}) {
  const { limit = 25, offset = 0, observableType, search } = options;
  const where: Prisma.InvestigationWhereInput = {
    ...(observableType ? { observableType: observableType as never } : {}),
    ...(search ? { normalizedObservable: { contains: search } } : {}),
  };

  const [items, total] = await Promise.all([
    prisma.investigation.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
      skip: offset,
      include: { providerResults: true, findings: true, relationships: true },
    }),
    prisma.investigation.count({ where }),
  ]);

  return { items: items.map(toInvestigation), total };
}

export async function deleteInvestigation(id: string): Promise<void> {
  await prisma.investigation.delete({ where: { id } });
}

export async function dashboardStats() {
  const [totalInvestigations, byStatus, recentFindings, findingsBySeverity, recent] = await Promise.all([
    prisma.investigation.count(),
    prisma.investigation.groupBy({ by: ["status"], _count: true }),
    prisma.finding.count(),
    prisma.finding.groupBy({ by: ["severity"], _count: true }),
    prisma.investigation.findMany({
      orderBy: { createdAt: "desc" },
      take: 8,
      select: { id: true, observable: true, observableType: true, status: true, createdAt: true },
    }),
  ]);

  return {
    totalInvestigations,
    byStatus: Object.fromEntries(byStatus.map((s) => [s.status, s._count])),
    totalFindings: recentFindings,
    findingsBySeverity: Object.fromEntries(findingsBySeverity.map((s) => [s.severity, s._count])),
    recent: recent.map((r) => ({ ...r, createdAt: r.createdAt.toISOString() })),
  };
}
