import "server-only";
import type { CaseItemKind, CaseStatus, Prisma } from "@prisma/client";
import { prisma } from "./client";

export interface CaseNoteData {
  text: string;
}
export interface CaseEvidenceData {
  label: string;
  sha256?: string;
  sha1?: string;
  md5?: string;
  description?: string;
  source?: string;
}
export interface CaseCustodyData {
  action: string;
  handler: string;
  detail?: string;
}
export interface CaseEventData {
  occurredAt: string;
  title: string;
  detail?: string;
  source?: string;
}
export interface CaseLinkData {
  refType: "investigation" | "ioc";
  refId: string;
  label?: string;
}
export type CaseItemData = CaseNoteData | CaseEvidenceData | CaseCustodyData | CaseEventData | CaseLinkData;

export interface CaseItemRecord {
  id: string;
  caseId: string;
  kind: CaseItemKind;
  createdAt: string;
  author: string;
  data: CaseItemData;
}

export interface CaseSummary {
  id: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  severity: string | null;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  itemCounts: Record<CaseItemKind, number>;
}

export interface CaseRecord extends CaseSummary {
  items: CaseItemRecord[];
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

function toItem(row: { id: string; caseId: string; kind: CaseItemKind; createdAt: Date; author: string; data: Prisma.JsonValue }): CaseItemRecord {
  return { id: row.id, caseId: row.caseId, kind: row.kind, createdAt: row.createdAt.toISOString(), author: row.author, data: row.data as unknown as CaseItemData };
}

function counts(items: { kind: CaseItemKind }[]): Record<CaseItemKind, number> {
  const c: Record<string, number> = { NOTE: 0, EVIDENCE: 0, CUSTODY: 0, EVENT: 0, LINK: 0 };
  for (const i of items) c[i.kind] = (c[i.kind] ?? 0) + 1;
  return c as Record<CaseItemKind, number>;
}

export async function listCases(options: { status?: CaseStatus; q?: string; limit?: number } = {}): Promise<CaseSummary[]> {
  const where: Prisma.CaseWhereInput = {
    ...(options.status ? { status: options.status } : {}),
    ...(options.q ? { OR: [{ title: { contains: options.q, mode: "insensitive" } }, { description: { contains: options.q, mode: "insensitive" } }] } : {}),
  };
  const rows = await prisma.case.findMany({ where, orderBy: { updatedAt: "desc" }, take: Math.min(options.limit ?? 200, 500), include: { items: { select: { kind: true } } } });
  return rows.map((r) => ({ id: r.id, title: r.title, description: r.description, status: r.status, severity: r.severity, tags: strings(r.tags), createdAt: r.createdAt.toISOString(), updatedAt: r.updatedAt.toISOString(), itemCounts: counts(r.items) }));
}

export async function getCase(id: string): Promise<CaseRecord | null> {
  const row = await prisma.case.findUnique({ where: { id }, include: { items: { orderBy: { createdAt: "asc" } } } });
  if (!row) return null;
  const items = row.items.map(toItem);
  return { id: row.id, title: row.title, description: row.description, status: row.status, severity: row.severity, tags: strings(row.tags), createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString(), itemCounts: counts(row.items), items };
}

export async function createCase(input: { title: string; description?: string; severity?: string; tags?: string[] }): Promise<CaseRecord> {
  const row = await prisma.case.create({ data: { title: input.title, description: input.description, severity: input.severity, tags: input.tags ?? [] }, include: { items: true } });
  return { id: row.id, title: row.title, description: row.description, status: row.status, severity: row.severity, tags: strings(row.tags), createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString(), itemCounts: counts([]), items: [] };
}

export async function updateCase(id: string, patch: { title?: string; description?: string | null; status?: CaseStatus; severity?: string | null; tags?: string[] }): Promise<void> {
  await prisma.case.update({ where: { id }, data: patch });
}

export async function deleteCase(id: string): Promise<void> {
  await prisma.case.delete({ where: { id } });
}

export async function addCaseItem(caseId: string, kind: CaseItemKind, data: CaseItemData, author = "operator"): Promise<CaseItemRecord> {
  const [row] = await prisma.$transaction([
    prisma.caseItem.create({ data: { caseId, kind, data: data as unknown as Prisma.InputJsonValue, author } }),
    prisma.case.update({ where: { id: caseId }, data: { updatedAt: new Date() } }),
  ]);
  return toItem(row);
}

export async function deleteCaseItem(caseId: string, itemId: string): Promise<void> {
  await prisma.caseItem.delete({ where: { id: itemId, caseId } });
}
