import type { NextRequest } from "next/server";
import { testProvider, type CheckResult } from "@/lib/db/health";
import { PROVIDERS } from "@/lib/providers/registry";
import { isConfigured } from "@/lib/providers/runtime";
import { assertSameOrigin, enforceLimits, handler, json } from "@/lib/server/api";

export const maxDuration = 120;

/** Tests every configured, testable source with bounded concurrency. Unconfigured keyed sources are reported, not called. */
export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req, { requireJson: false });
  await enforceLimits(req, [
    { name: "provider-test-all", limit: 3, windowSeconds: 600, scope: "client" },
    { name: "provider-test-all", limit: 12, windowSeconds: 3600, scope: "global" },
  ]);
  const targets = PROVIDERS.filter((p) => p.healthCheck && isConfigured(p));
  const results: CheckResult[] = [];
  const queue = [...targets];
  await Promise.all(
    Array.from({ length: 5 }, async () => {
      for (let def = queue.shift(); def; def = queue.shift()) {
        try {
          results.push(await testProvider(def));
        } catch (err) {
          results.push({ provider: def.id, state: "ERROR", status: "UNAVAILABLE", latencyMs: 0, checkedAt: new Date().toISOString(), message: (err as Error).message });
        }
      }
    })
  );
  return json({ results, skipped: PROVIDERS.filter((p) => p.healthCheck && !isConfigured(p)).map((p) => p.id) });
});
