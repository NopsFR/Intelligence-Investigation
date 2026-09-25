import { prisma } from "@/lib/db/client";
import { json } from "@/lib/server/api";

/** Liveness + database reachability. Deliberately reveals nothing about configuration. */
export async function GET() {
  const started = Date.now();
  try {
    await prisma.$queryRaw`SELECT 1`;
    return json({ ok: true, database: { ok: true, latencyMs: Date.now() - started }, time: new Date().toISOString() });
  } catch {
    return json({ ok: false, database: { ok: false }, time: new Date().toISOString() }, { status: 503 });
  }
}
