import "server-only";
import type { Prisma } from "@prisma/client";
import type { ObservableType } from "@/lib/core/types";
import { prisma } from "./client";

export interface IocRecord {
  id: string;
  value: string;
  type: ObservableType;
  tags: string[];
  notes: string | null;
  source: string | null;
  createdAt: string;
  updatedAt: string;
  investigationIds: string[];
  lastInvestigation?: { id: string; createdAt: string; status: string; summary: string };
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

export function normalizeTags(tags: string[]): string[] {
  return [...new Set(tags.map((t) => t.trim().toLowerCase().replace(/\s+/g, "-").slice(0, 40)).filter(Boolean))].slice(0, 20);
}

export async function listIocs(options: { q?: string; type?: ObservableType; tag?: string; limit?: number } = {}): Promise<IocRecord[]> {
  const where: Prisma.IocEntryWhereInput = {
    ...(options.q ? { OR: [{ value: { contains: options.q.toLowerCase() } }, { notes: { contains: options.q, mode: "insensitive" } }] } : {}),
    ...(options.type ? { type: options.type } : {}),
    ...(options.tag ? { tags: { array_contains: [options.tag] } } : {}),
  };
  const rows = await prisma.iocEntry.findMany({ where, orderBy: { updatedAt: "desc" }, take: Math.min(options.limit ?? 500, 2000) });
  const values = rows.map((r) => r.value);
  const latest = values.length
    ? await prisma.investigation.findMany({
        where: { normalizedObservable: { in: values } },
        orderBy: { createdAt: "desc" },
        select: { id: true, createdAt: true, status: true, summary: true, normalizedObservable: true, observableType: true },
      })
    : [];
  return rows.map((r) => {
    const inv = latest.find((i) => i.normalizedObservable === r.value && i.observableType === r.type);
    return {
      id: r.id,
      value: r.value,
      type: r.type as ObservableType,
      tags: strings(r.tags),
      notes: r.notes,
      source: r.source,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
      investigationIds: strings(r.investigationRefIds),
      lastInvestigation: inv ? { id: inv.id, createdAt: inv.createdAt.toISOString(), status: inv.status, summary: inv.summary ?? "" } : undefined,
    };
  });
}

export async function addIocs(entries: { value: string; type: ObservableType; tags?: string[]; notes?: string; source?: string; investigationId?: string }[]) {
  let created = 0;
  let updated = 0;
  for (const e of entries.slice(0, 1000)) {
    const existing = await prisma.iocEntry.findUnique({ where: { value_type: { value: e.value, type: e.type } } });
    if (existing) {
      await prisma.iocEntry.update({
        where: { id: existing.id },
        data: {
          tags: normalizeTags([...strings(existing.tags), ...(e.tags ?? [])]),
          notes: e.notes ?? existing.notes,
          investigationRefIds: [...new Set([...strings(existing.investigationRefIds), ...(e.investigationId ? [e.investigationId] : [])])],
        },
      });
      updated++;
    } else {
      await prisma.iocEntry.create({
        data: { value: e.value, type: e.type, tags: normalizeTags(e.tags ?? []), notes: e.notes ?? null, source: e.source ?? null, investigationRefIds: e.investigationId ? [e.investigationId] : [] },
      });
      created++;
    }
  }
  return { created, updated };
}

export async function updateIoc(id: string, patch: { tags?: string[]; notes?: string | null }) {
  return prisma.iocEntry.update({ where: { id }, data: { ...(patch.tags ? { tags: normalizeTags(patch.tags) } : {}), ...(patch.notes !== undefined ? { notes: patch.notes } : {}) } });
}

export async function deleteIocs(ids: string[]) {
  const res = await prisma.iocEntry.deleteMany({ where: { id: { in: ids } } });
  return res.count;
}

// ------------------------------------------------------------------ export

function csvCell(v: string): string {
  // Neutralise spreadsheet formula injection as well as quoting.
  const safe = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function iocsToCsv(items: IocRecord[]): string {
  const lines = ["type,value,tags,notes,source,created,updated"];
  for (const i of items) lines.push([i.type, i.value, i.tags.join(" "), i.notes ?? "", i.source ?? "", i.createdAt, i.updatedAt].map(csvCell).join(","));
  return lines.join("\n") + "\n";
}

const STIX_PATTERN: Partial<Record<ObservableType, (v: string) => string>> = {
  IPV4: (v) => `[ipv4-addr:value = '${v}']`,
  IPV6: (v) => `[ipv6-addr:value = '${v}']`,
  DOMAIN: (v) => `[domain-name:value = '${v}']`,
  URL: (v) => `[url:value = '${v.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}']`,
  EMAIL: (v) => `[email-addr:value = '${v}']`,
  MD5: (v) => `[file:hashes.MD5 = '${v}']`,
  SHA1: (v) => `[file:hashes.'SHA-1' = '${v}']`,
  SHA256: (v) => `[file:hashes.'SHA-256' = '${v}']`,
  CERT_SHA256: (v) => `[x509-certificate:hashes.'SHA-256' = '${v}']`,
};

/** Deterministic UUIDv5-style id so re-exports of the same indicator keep their STIX id. */
async function stixId(kind: string, value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(`nops:${kind}:${value}`)));
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = [...digest.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${kind}--${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/** STIX 2.1 bundle of indicator objects (types without a STIX pattern — CVE, ASN — are left out). */
export async function iocsToStix(items: IocRecord[]) {
  const objects = [];
  for (const i of items) {
    const pattern = STIX_PATTERN[i.type]?.(i.value);
    if (!pattern) continue;
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: await stixId("indicator", `${i.type}:${i.value}`),
      created: i.createdAt,
      modified: i.updatedAt,
      name: i.value,
      description: i.notes ?? undefined,
      indicator_types: ["unknown"],
      pattern,
      pattern_type: "stix",
      valid_from: i.createdAt,
      labels: i.tags.length ? i.tags : undefined,
    });
  }
  return { type: "bundle", id: await stixId("bundle", `${Date.now()}`), objects };
}
