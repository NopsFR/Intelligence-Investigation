import { prisma } from "@/lib/db/client";
import { connectionState, type ConnectionState } from "@/lib/db/health";
import { PROVIDERS } from "@/lib/providers/registry";
import { isConfigured } from "@/lib/providers/runtime";
import { handler, json } from "@/lib/server/api";

/** Compact operational status for the shell's status bar. */
export const GET = handler(async () => {
  const started = Date.now();
  let db: { ok: boolean; latencyMs?: number } = { ok: false };
  let running = 0;
  const states: Partial<Record<ConnectionState, number>> = {};
  const external = PROVIDERS.filter((p) => p.kind === "external");
  try {
    await prisma.$queryRaw`SELECT 1`;
    db = { ok: true, latencyMs: Date.now() - started };
    const [count, health] = await Promise.all([prisma.investigation.count({ where: { status: "RUNNING" } }), prisma.apiProviderHealth.findMany({ select: { provider: true, lastStatus: true } })]);
    running = count;
    const by = new Map(health.map((h) => [h.provider, h.lastStatus]));
    for (const p of external) {
      const s = isConfigured(p) ? connectionState(by.get(p.id)) : "NOT_CONFIGURED";
      states[s] = (states[s] ?? 0) + 1;
    }
  } catch {
    db = { ok: false };
  }
  return json({ db, running, sources: { external: external.length, configured: external.filter((p) => isConfigured(p)).length, states }, commit: process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7), region: process.env.VERCEL_REGION });
});
