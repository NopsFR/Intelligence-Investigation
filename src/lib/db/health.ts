import "server-only";
import type { ProviderOutcome, ProviderStatus } from "@/lib/core/types";
import { services } from "@/lib/engine/investigate";
import { PROVIDERS } from "@/lib/providers/registry";
import { executeProvider, isConfigured, readApiKey } from "@/lib/providers/runtime";
import type { ProviderDefinition, QuotaSpec } from "@/lib/providers/types";
import { prisma } from "./client";
import { peekBucket } from "./stores";

/** Connection state shown in the API Observatory. */
export type ConnectionState = "CONNECTED" | "NOT_CONFIGURED" | "AUTH_FAILED" | "RATE_LIMITED" | "TIMEOUT" | "UNAVAILABLE" | "ERROR" | "UNTESTED" | "LOCAL";

export function connectionState(status: ProviderStatus | string | null | undefined): ConnectionState {
  switch (status) {
    case "SUCCESS":
    case "PARTIAL":
    case "EMPTY":
      return "CONNECTED";
    case "NOT_CONFIGURED":
      return "NOT_CONFIGURED";
    case "AUTH_FAILED":
      return "AUTH_FAILED";
    case "RATE_LIMITED":
      return "RATE_LIMITED";
    case "TIMEOUT":
      return "TIMEOUT";
    case "NETWORK_ERROR":
    case "UNAVAILABLE":
      return "UNAVAILABLE";
    case "INVALID_RESPONSE":
    case "SKIPPED":
      return "ERROR";
    default:
      return "UNTESTED";
  }
}

export interface CheckResult {
  provider: string;
  state: ConnectionState;
  status: ProviderStatus;
  latencyMs: number;
  checkedAt: string;
  httpStatus?: number;
  errorType?: string;
  message: string;
  sample?: string;
}

/** Runs a real request against the provider with a known observable. */
export async function testProvider(def: ProviderDefinition): Promise<CheckResult> {
  if (!def.healthCheck) throw new Error(`${def.name} has no connection test`);
  const outcome: ProviderOutcome = await executeProvider(def, { observable: def.healthCheck.observable, type: def.healthCheck.type, mode: "QUICK", fresh: true }, services);
  const state = connectionState(outcome.status);
  const message =
    state === "CONNECTED"
      ? `Answered for ${def.healthCheck.observable}${outcome.result?.summary ? `: ${outcome.result.summary}` : ""}`
      : outcome.errorMessage ?? outcome.status;
  const checkedAt = new Date();
  await prisma.$transaction([
    prisma.providerCheck.create({ data: { provider: def.id, checkedAt, status: outcome.status, latencyMs: outcome.latencyMs, errorType: outcome.errorType ?? null, message: message.slice(0, 500) } }),
    prisma.apiProviderHealth.upsert({
      where: { provider: def.id },
      create: { provider: def.id, configured: isConfigured(def), lastCheckedAt: checkedAt, lastStatus: outcome.status, lastLatencyMs: outcome.latencyMs, lastError: state === "CONNECTED" ? null : message.slice(0, 500), lastErrorType: outcome.errorType ?? null },
      update: { configured: isConfigured(def), lastCheckedAt: checkedAt, lastStatus: outcome.status, lastLatencyMs: outcome.latencyMs, lastError: state === "CONNECTED" ? null : message.slice(0, 500), lastErrorType: outcome.errorType ?? null },
    }),
  ]);
  // Keep the check history bounded.
  const stale = await prisma.providerCheck.findMany({ where: { provider: def.id }, orderBy: { checkedAt: "desc" }, skip: 50, select: { id: true } });
  if (stale.length) await prisma.providerCheck.deleteMany({ where: { id: { in: stale.map((s) => s.id) } } });
  return {
    provider: def.id,
    state,
    status: outcome.status,
    latencyMs: outcome.latencyMs,
    checkedAt: checkedAt.toISOString(),
    httpStatus: outcome.httpStatus,
    errorType: outcome.errorType,
    message,
    sample: outcome.result?.summary,
  };
}

function quotasFor(def: ProviderDefinition): QuotaSpec[] {
  return typeof def.quotas === "function" ? def.quotas({ hasKey: Boolean(readApiKey(def)) }) : def.quotas ?? [];
}

export interface ProviderSnapshot {
  id: string;
  name: string;
  vendor: string;
  category: string;
  kind: string;
  active: boolean;
  description: string;
  homepage: string;
  docs?: string;
  endpoint: string;
  limits?: string;
  terms?: string;
  supports: string[];
  auth: { type: string; env?: readonly string[]; signup?: string; benefit?: string; keyPresent: boolean };
  configured: boolean;
  testable: boolean;
  healthCheck?: { observable: string; type: string };
  state: ConnectionState;
  lastCheck?: { at: string; status: string; latencyMs?: number; errorType?: string; message?: string };
  checks: { at: string; status: string; latencyMs?: number }[];
  usage: { total: number; answered: number; failed: number; cached: number; avgLatencyMs?: number; p95LatencyMs?: number; lastUsedAt?: string; byStatus: Record<string, number> };
  quotas: { label: string; limit: number; windowSeconds: number; used: number }[];
  cacheTtlSeconds: number;
  timeoutMs: number;
}

export async function observatorySnapshot(): Promise<{ providers: ProviderSnapshot[]; generatedAt: string; windowHours: number }> {
  const windowHours = 24;
  const since = new Date(Date.now() - windowHours * 3600 * 1000);
  const [health, checks, usage] = await Promise.all([
    prisma.apiProviderHealth.findMany(),
    prisma.providerCheck.findMany({ where: { checkedAt: { gt: new Date(Date.now() - 14 * 86400 * 1000) } }, orderBy: { checkedAt: "desc" }, take: 2000 }),
    prisma.providerResult.findMany({ where: { retrievedAt: { gt: since } }, select: { provider: true, status: true, latencyMs: true, cached: true, retrievedAt: true } }),
  ]);
  const healthBy = new Map(health.map((h) => [h.provider, h]));

  const providers = await Promise.all(
    PROVIDERS.map(async (def): Promise<ProviderSnapshot> => {
      const h = healthBy.get(def.id);
      const mine = usage.filter((u) => u.provider === def.id);
      const live = mine.filter((u) => !u.cached && u.latencyMs !== null && u.status !== "SKIPPED" && u.status !== "NOT_CONFIGURED").map((u) => u.latencyMs!).sort((a, b) => a - b);
      const byStatus: Record<string, number> = {};
      for (const u of mine) byStatus[u.status] = (byStatus[u.status] ?? 0) + 1;
      const answered = mine.filter((u) => ["SUCCESS", "PARTIAL", "EMPTY"].includes(u.status)).length;
      const failed = mine.filter((u) => ["RATE_LIMITED", "AUTH_FAILED", "TIMEOUT", "NETWORK_ERROR", "INVALID_RESPONSE", "UNAVAILABLE"].includes(u.status)).length;
      const configured = isConfigured(def);
      const quotas = await Promise.all(
        quotasFor(def).map(async (q) => ({ label: q.label, limit: q.limit, windowSeconds: q.windowSeconds, used: await peekBucket(`provider:${def.id}:${q.windowSeconds}`, q.windowSeconds).catch(() => 0) }))
      );
      const lastUse = mine.reduce<Date | null>((latest, u) => (!latest || u.retrievedAt > latest ? u.retrievedAt : latest), null);
      let state: ConnectionState = def.kind === "external" ? connectionState(h?.lastStatus) : "LOCAL";
      if (!configured) state = "NOT_CONFIGURED";
      else if (state === "NOT_CONFIGURED") state = "UNTESTED"; // key added since the last test
      return {
        id: def.id,
        name: def.name,
        vendor: def.vendor,
        category: def.category,
        kind: def.kind,
        active: Boolean(def.active),
        description: def.description,
        homepage: def.homepage,
        docs: def.docs,
        endpoint: def.endpoint,
        limits: def.limits,
        terms: def.terms,
        supports: def.supports,
        auth:
          def.auth.type === "none"
            ? { type: "none", keyPresent: false }
            : { type: def.auth.type, env: def.auth.env, signup: def.auth.signup, benefit: def.auth.type === "optional" ? def.auth.benefit : undefined, keyPresent: Boolean(readApiKey(def)) },
        configured,
        testable: Boolean(def.healthCheck),
        healthCheck: def.healthCheck,
        state,
        lastCheck: h?.lastCheckedAt ? { at: h.lastCheckedAt.toISOString(), status: h.lastStatus ?? "", latencyMs: h.lastLatencyMs ?? undefined, errorType: h.lastErrorType ?? undefined, message: h.lastError ?? undefined } : undefined,
        checks: checks.filter((c) => c.provider === def.id).slice(0, 30).map((c) => ({ at: c.checkedAt.toISOString(), status: c.status, latencyMs: c.latencyMs ?? undefined })),
        usage: {
          total: mine.length,
          answered,
          failed,
          cached: mine.filter((u) => u.cached).length,
          avgLatencyMs: live.length ? Math.round(live.reduce((a, b) => a + b, 0) / live.length) : undefined,
          p95LatencyMs: live.length ? live[Math.min(live.length - 1, Math.floor(live.length * 0.95))] : undefined,
          lastUsedAt: lastUse?.toISOString(),
          byStatus,
        },
        quotas,
        cacheTtlSeconds: def.cacheTtlSeconds,
        timeoutMs: def.timeoutMs,
      };
    })
  );
  return { providers, generatedAt: new Date().toISOString(), windowHours };
}

