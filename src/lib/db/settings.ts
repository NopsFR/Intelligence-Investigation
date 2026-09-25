import "server-only";
import { PROVIDERS } from "@/lib/providers/registry";
import { readApiKey } from "@/lib/providers/runtime";
import { ALLOWED_TARGET_PORTS } from "@/lib/net/policy";
import { operatorConfigured } from "@/lib/server/session";
import { prisma } from "./client";

export interface SettingsData {
  deployment: { version: string; commit?: string; environment: string; region?: string; node: string };
  security: {
    operatorConfigured: boolean;
    operator: boolean;
    privateMode: boolean;
    sessionSecretSet: boolean;
    csp: string;
    targetPorts: number[];
    limits: { name: string; rule: string }[];
  };
  database: {
    connected: boolean;
    latencyMs?: number;
    engine: string;
    host?: string;
    database?: string;
    migrations: { name: string; appliedAt: string }[];
    counts: Record<string, number>;
    cache: { active: number; expired: number };
    error?: string;
  };
  keys: { provider: string; name: string; requirement: string; env: string[]; present: boolean; signup: string; benefit?: string }[];
}

function databaseTarget(): { host?: string; database?: string } {
  try {
    const url = new URL(process.env.DATABASE_URL ?? "");
    return { host: url.hostname, database: url.pathname.replace(/^\//, "") || undefined };
  } catch {
    return {};
  }
}

export async function settingsData(operator: boolean): Promise<SettingsData> {
  const started = Date.now();
  let database: SettingsData["database"];
  try {
    await prisma.$queryRaw`SELECT 1`;
    const latencyMs = Date.now() - started;
    const [investigations, results, findings, relationships, iocs, observables, checks, cacheActive, cacheExpired, migrations] = await Promise.all([
      prisma.investigation.count(),
      prisma.providerResult.count(),
      prisma.finding.count(),
      prisma.relationship.count(),
      prisma.iocEntry.count(),
      prisma.observable.count(),
      prisma.providerCheck.count(),
      prisma.providerCache.count({ where: { expiresAt: { gt: new Date() } } }),
      prisma.providerCache.count({ where: { expiresAt: { lte: new Date() } } }),
      prisma
        .$queryRaw<{ migration_name: string; finished_at: Date | null }[]>`SELECT migration_name, finished_at FROM "_prisma_migrations" WHERE rolled_back_at IS NULL ORDER BY finished_at`
        .catch(() => [] as { migration_name: string; finished_at: Date | null }[]),
    ]);
    const target = databaseTarget();
    database = {
      connected: true,
      latencyMs,
      engine: "PostgreSQL",
      ...(operator ? target : {}),
      migrations: migrations.map((m) => ({ name: m.migration_name, appliedAt: m.finished_at?.toISOString() ?? "" })),
      counts: { investigations, providerResults: results, findings, relationships, iocs, observables, providerChecks: checks },
      cache: { active: cacheActive, expired: cacheExpired },
    };
  } catch (err) {
    database = { connected: false, engine: "PostgreSQL", migrations: [], counts: {}, cache: { active: 0, expired: 0 }, error: (err as Error).message.split("\n")[0].slice(0, 200) };
  }

  return {
    deployment: {
      version: process.env.npm_package_version ?? "2.0.0",
      commit: process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7),
      environment: process.env.VERCEL_ENV ?? process.env.NODE_ENV ?? "development",
      region: process.env.VERCEL_REGION,
      node: process.version,
    },
    security: {
      operatorConfigured: operatorConfigured(),
      operator,
      privateMode: process.env.NOPS_PRIVATE === "1",
      sessionSecretSet: Boolean(process.env.NOPS_SESSION_SECRET),
      csp: "Per-request nonce, strict-dynamic scripts, no third-party origins, frame-ancestors 'none'",
      targetPorts: [...ALLOWED_TARGET_PORTS],
      limits: [
        { name: "Investigations", rule: "12 per minute per client · 400 per hour instance-wide" },
        { name: "Connection tests", rule: "20 per 5 minutes per client · 30 per hour per source" },
        { name: "Test all sources", rule: "3 per 10 minutes per client" },
        { name: "DNS lookup tool", rule: "60 per minute per client" },
        { name: "Operator unlock", rule: "10 attempts per 15 minutes per client" },
      ],
    },
    database,
    keys: PROVIDERS.filter((p) => p.auth.type !== "none").map((p) => ({
      provider: p.id,
      name: p.name,
      requirement: p.auth.type,
      env: p.auth.type === "none" ? [] : [...p.auth.env],
      present: Boolean(readApiKey(p)),
      signup: p.auth.type === "none" ? "" : p.auth.signup,
      benefit: p.auth.type === "optional" ? p.auth.benefit : undefined,
    })),
  };
}
