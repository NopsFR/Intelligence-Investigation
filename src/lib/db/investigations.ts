import "server-only";
import type { Prisma, Investigation, ProviderResult, Finding, Relationship } from "@prisma/client";
import {
  ANSWERED_STATUSES,
  NEUTRAL_STATUSES,
  SEVERITIES,
  type Fact,
  type FindingRecord,
  type InvestigationMode,
  type InvestigationRecord,
  type InvestigationStatus,
  type InvestigationSummary,
  type NodeRef,
  type NodeType,
  type NormalizedResult,
  type ObservableType,
  type PlanStep,
  type ProviderDiagnostics,
  type ProviderOutcome,
  type ProviderStatus,
  type Reference,
  type RelationshipRecord,
  type Severity,
} from "@/lib/core/types";
import { prisma } from "./client";

/** An investigation still RUNNING after this long has lost its worker. */
export const STALE_AFTER_MS = 4 * 60 * 1000;

const NODE_TYPES = new Set<NodeType>(["ip", "domain", "url", "email", "hash", "asn", "prefix", "certificate", "malware", "cve", "technique", "software", "group", "product", "port", "organization"]);

function toNodeType(value: string): NodeType {
  const v = value.toLowerCase();
  if (NODE_TYPES.has(v as NodeType)) return v as NodeType;
  if (v === "ipv4" || v === "ipv6") return "ip";
  if (v === "md5" || v === "sha1" || v === "sha256") return "hash";
  if (v === "cert_sha256") return "certificate";
  return "organization";
}

/** Accepts current results and the v1 shape ({ summary, fields: [{label, value}] }). */
function toResult(value: unknown): NormalizedResult | undefined {
  if (!value || typeof value !== "object") return undefined;
  const r = value as Record<string, unknown>;
  if (Array.isArray(r.facts)) return r as unknown as NormalizedResult;
  const fields = Array.isArray(r.fields) ? (r.fields as { label?: unknown; value?: unknown }[]) : [];
  const facts: Fact[] = fields
    .filter((f) => typeof f.label === "string" && f.value !== undefined && f.value !== null)
    .map((f) => ({ key: String(f.label), label: String(f.label), value: Array.isArray(f.value) ? f.value.map(String) : typeof f.value === "object" ? JSON.stringify(f.value) : (f.value as string | number | boolean) }));
  return { summary: typeof r.summary === "string" ? r.summary : "", facts };
}

export function toOutcome(row: ProviderResult): ProviderOutcome {
  return {
    provider: row.provider,
    status: row.status as ProviderStatus,
    latencyMs: row.latencyMs ?? 0,
    startedAt: row.startedAt?.toISOString(),
    retrievedAt: row.retrievedAt.toISOString(),
    cached: row.cached || undefined,
    httpStatus: row.httpStatus ?? undefined,
    errorType: row.errorType ?? undefined,
    errorMessage: row.errorMessage ?? undefined,
    result: toResult(row.result),
    diagnostics: (row.diagnostics as ProviderDiagnostics | null) ?? undefined,
  };
}

function toFinding(row: Finding): FindingRecord {
  return {
    id: row.id,
    rule: row.rule,
    severity: (SEVERITIES.includes(row.severity as Severity) ? row.severity : "INFO") as Severity,
    category: row.category,
    title: row.title,
    description: row.description,
    rationale: row.rationale ?? undefined,
    evidence: row.evidence,
    evidenceData: (row.evidenceData as FindingRecord["evidenceData"] | null) ?? undefined,
    observable: row.observable ?? undefined,
    confidence: row.confidence ?? undefined,
    remediation: row.remediation ?? undefined,
    references: (row.references as Reference[] | null) ?? undefined,
    source: row.source,
    observedAt: row.observedAt.toISOString(),
  };
}

/** Merges identical edges reported by several providers into one record with combined provenance. */
function mergeRelationships(rows: Relationship[]): RelationshipRecord[] {
  const byKey = new Map<string, RelationshipRecord>();
  for (const r of rows) {
    const source: NodeRef = { type: toNodeType(r.sourceType), value: r.sourceValue };
    const target: NodeRef = { type: toNodeType(r.targetType), value: r.targetValue, ...(r.targetLabel ? { label: r.targetLabel } : {}) };
    const key = `${source.type}:${source.value.toLowerCase()}|${r.relationType}|${target.type}:${target.value.toLowerCase()}`;
    const existing = byKey.get(key);
    if (existing) {
      if (!existing.providers.includes(r.provider)) existing.providers.push(r.provider);
      if (!existing.evidence.includes(r.evidence)) existing.evidence.push(r.evidence);
      if (!existing.target.label && target.label) existing.target.label = target.label;
    } else {
      byKey.set(key, { id: r.id, source, target, type: r.relationType, providers: [r.provider], evidence: [r.evidence], observedAt: r.observedAt.toISOString() });
    }
  }
  return [...byKey.values()];
}

function toPlan(value: unknown): PlanStep[] {
  return Array.isArray(value) ? (value as PlanStep[]).filter((s) => s && typeof s.id === "string") : [];
}

type FullInvestigation = Investigation & { providerResults: ProviderResult[]; findings: Finding[]; relationships: Relationship[] };

export function toRecord(row: FullInvestigation): InvestigationRecord {
  return {
    id: row.id,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    completedAt: row.completedAt?.toISOString(),
    durationMs: row.durationMs ?? undefined,
    observable: row.observable,
    observableType: row.observableType as ObservableType,
    normalizedObservable: row.normalizedObservable,
    mode: row.mode as InvestigationMode,
    status: row.status as InvestigationStatus,
    summary: row.summary ?? "",
    plan: toPlan(row.plan),
    previousId: row.previousId ?? undefined,
    providerResults: row.providerResults.map(toOutcome),
    findings: row.findings.map(toFinding),
    relationships: mergeRelationships(row.relationships),
  };
}

export function countFindings(findings: { severity: string }[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) if (f.severity in counts) counts[f.severity as Severity]++;
  return counts;
}

export function countProviders(results: { status: string }[]) {
  const answered = results.filter((r) => ANSWERED_STATUSES.has(r.status as ProviderStatus)).length;
  const notConfigured = results.filter((r) => r.status === "NOT_CONFIGURED").length;
  const neutral = results.filter((r) => NEUTRAL_STATUSES.has(r.status as ProviderStatus)).length;
  return { total: results.length, answered, failed: results.length - answered - neutral, notConfigured };
}

const include = { providerResults: { orderBy: { retrievedAt: "asc" } }, findings: { orderBy: { observedAt: "asc" } }, relationships: true } as const;

export async function getInvestigation(id: string): Promise<InvestigationRecord | null> {
  const row = await prisma.investigation.findUnique({ where: { id }, include });
  if (!row) return null;
  if (row.status === "RUNNING" && Date.now() - row.updatedAt.getTime() > STALE_AFTER_MS) {
    await abandonInvestigation(row);
    return getInvestigation(id);
  }
  return toRecord(row);
}

/**
 * The worker for a RUNNING investigation died (function timeout, redeploy).
 * Record every unfinished step honestly and close the investigation.
 */
async function abandonInvestigation(row: FullInvestigation) {
  const done = new Set(row.providerResults.map((r) => r.provider));
  const missing = toPlan(row.plan).filter((s) => !done.has(s.id));
  await prisma.$transaction([
    ...missing.map((s) =>
      prisma.providerResult.upsert({
        where: { investigationId_provider: { investigationId: row.id, provider: s.id } },
        create: { investigationId: row.id, provider: s.id, status: "TIMEOUT", errorType: "worker-stopped", errorMessage: "The investigation worker stopped before this source finished." },
        update: {},
      })
    ),
    prisma.investigation.update({
      where: { id: row.id },
      data: {
        status: row.providerResults.some((r) => ANSWERED_STATUSES.has(r.status as ProviderStatus)) ? "PARTIAL" : "FAILED",
        completedAt: new Date(),
        durationMs: Date.now() - row.createdAt.getTime(),
        summary: row.summary ?? `Stopped before completion · ${missing.length} source(s) did not finish`,
      },
    }),
  ]);
}

export interface ListOptions {
  q?: string;
  type?: ObservableType;
  status?: InvestigationStatus;
  severity?: Severity;
  limit?: number;
  cursor?: string;
}

export async function listInvestigations(options: ListOptions = {}): Promise<{ items: InvestigationSummary[]; nextCursor?: string }> {
  const limit = Math.min(Math.max(options.limit ?? 30, 1), 100);
  const where: Prisma.InvestigationWhereInput = {
    ...(options.q ? { OR: [{ normalizedObservable: { contains: options.q.toLowerCase() } }, { observable: { contains: options.q, mode: "insensitive" } }] } : {}),
    ...(options.type ? { observableType: options.type } : {}),
    ...(options.status ? { status: options.status } : {}),
    ...(options.severity ? { findings: { some: { severity: options.severity } } } : {}),
  };
  const rows = await prisma.investigation.findMany({
    where,
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: limit + 1,
    ...(options.cursor ? { cursor: { id: options.cursor }, skip: 1 } : {}),
    include: { findings: { select: { severity: true } }, providerResults: { select: { status: true } } },
  });
  const items = rows.slice(0, limit).map(
    (r): InvestigationSummary => ({
      id: r.id,
      createdAt: r.createdAt.toISOString(),
      completedAt: r.completedAt?.toISOString(),
      durationMs: r.durationMs ?? undefined,
      observable: r.observable,
      observableType: r.observableType as ObservableType,
      normalizedObservable: r.normalizedObservable,
      mode: r.mode as InvestigationMode,
      status: r.status as InvestigationStatus,
      summary: r.summary ?? "",
      findingCounts: countFindings(r.findings),
      providerCounts: countProviders(r.providerResults),
    })
  );
  return { items, nextCursor: rows.length > limit ? rows[limit - 1].id : undefined };
}

export async function deleteInvestigation(id: string): Promise<boolean> {
  const res = await prisma.investigation.deleteMany({ where: { id } });
  return res.count > 0;
}

/** Earlier investigations of the same observable, newest first. */
export async function investigationHistory(normalizedObservable: string, type: ObservableType, excludeId?: string) {
  const rows = await prisma.investigation.findMany({
    where: { normalizedObservable, observableType: type, ...(excludeId ? { id: { not: excludeId } } : {}) },
    orderBy: { createdAt: "desc" },
    take: 20,
    select: { id: true, createdAt: true, mode: true, status: true, summary: true, findings: { select: { severity: true } } },
  });
  return rows.map((r) => ({ id: r.id, createdAt: r.createdAt.toISOString(), mode: r.mode, status: r.status, summary: r.summary ?? "", findingCounts: countFindings(r.findings) }));
}
