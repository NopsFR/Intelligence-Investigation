import "server-only";
import type { Prisma } from "@prisma/client";
import type { NormalizedResult, ProviderDiagnostics, ProviderOutcome, ProviderStatus } from "@/lib/core/types";
import type { CacheStore, QuotaStore } from "@/lib/providers/runtime";
import { prisma } from "./client";

export const cacheStore: CacheStore = {
  async get(provider, key) {
    const row = await prisma.providerCache.findUnique({ where: { provider_cacheKey: { provider, cacheKey: key } } });
    if (!row || row.expiresAt.getTime() <= Date.now()) return null;
    return {
      provider,
      status: row.status as ProviderStatus,
      latencyMs: row.latencyMs ?? 0,
      retrievedAt: row.retrievedAt.toISOString(),
      httpStatus: row.httpStatus ?? undefined,
      result: (row.result as unknown as NormalizedResult) ?? undefined,
      raw: row.raw ?? undefined,
      diagnostics: (row.diagnostics as unknown as ProviderDiagnostics) ?? undefined,
    };
  },
  async set(provider, key, outcome: ProviderOutcome, ttlSeconds) {
    const data = {
      status: outcome.status,
      result: (outcome.result ?? undefined) as Prisma.InputJsonValue | undefined,
      raw: (outcome.raw ?? undefined) as Prisma.InputJsonValue | undefined,
      diagnostics: (outcome.diagnostics ?? undefined) as Prisma.InputJsonValue | undefined,
      httpStatus: outcome.httpStatus ?? null,
      latencyMs: outcome.latencyMs,
      retrievedAt: new Date(outcome.retrievedAt),
      expiresAt: new Date(Date.now() + ttlSeconds * 1000),
    };
    await prisma.providerCache.upsert({ where: { provider_cacheKey: { provider, cacheKey: key } }, create: { provider, cacheKey: key, ...data }, update: data });
    if (Math.random() < 0.02) await prisma.providerCache.deleteMany({ where: { expiresAt: { lt: new Date() } } }).catch(() => undefined);
  },
};

/**
 * Fixed-window counter shared by all serverless instances. Atomic: the
 * increment and the read happen in one statement.
 */
export async function consumeBucket(key: string, limit: number, windowSeconds: number): Promise<{ allowed: boolean; count: number; resetAt: Date }> {
  const windowMs = windowSeconds * 1000;
  const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
  const resetAt = new Date(windowStart.getTime() + windowMs);
  const rows = await prisma.$queryRaw<{ count: number }[]>`
    INSERT INTO "RateLimitBucket" ("key", "windowStart", "count", "expiresAt")
    VALUES (${key}, ${windowStart}, 1, ${resetAt})
    ON CONFLICT ("key", "windowStart") DO UPDATE SET "count" = "RateLimitBucket"."count" + 1
    RETURNING "count"`;
  if (Math.random() < 0.02) await prisma.rateLimitBucket.deleteMany({ where: { expiresAt: { lt: new Date() } } }).catch(() => undefined);
  const count = Number(rows[0]?.count ?? 1);
  return { allowed: count <= limit, count, resetAt };
}

export const quotaStore: QuotaStore = {
  async consume(key, limit, windowSeconds) {
    return (await consumeBucket(key, limit, windowSeconds)).allowed;
  },
};

/** Current usage of a quota window without consuming it. */
export async function peekBucket(key: string, windowSeconds: number): Promise<number> {
  const windowMs = windowSeconds * 1000;
  const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
  const row = await prisma.rateLimitBucket.findUnique({ where: { key_windowStart: { key, windowStart } } });
  return row?.count ?? 0;
}
