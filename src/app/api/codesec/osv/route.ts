import type { NextRequest } from "next/server";
import { z } from "zod";
import { assertSameOrigin, enforceLimits, handler, json, readJson } from "@/lib/server/api";
import { osvQuerySchema } from "@/lib/server/schemas";

// Server-side proxy to OSV.dev's keyless batch query API. The dependency
// file never leaves the browser except as (name, version, ecosystem)
// triples — no source code or file paths are sent.

const osvVuln = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional(),
  affected: z
    .array(
      z.object({
        ranges: z.array(z.object({ type: z.string(), events: z.array(z.record(z.string(), z.string())) })).optional(),
        versions: z.array(z.string()).optional(),
      })
    )
    .optional(),
  references: z.array(z.object({ type: z.string(), url: z.string() })).optional(),
  published: z.string().optional(),
  modified: z.string().optional(),
});
const batchSchema = z.object({ results: z.array(z.object({ vulns: z.array(osvVuln).optional() })) });

const MAX_BATCH = 100;

export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  const { packages } = await readJson(req, osvQuerySchema, 512 * 1024);
  await enforceLimits(req, [
    { name: "osv-query", limit: 30, windowSeconds: 3600, scope: "client" },
    { name: "osv-query-global", limit: 600, windowSeconds: 3600, scope: "global" },
  ]);

  const results: Record<string, z.infer<typeof osvVuln>[]> = {};
  const errors: string[] = [];
  for (let i = 0; i < packages.length; i += MAX_BATCH) {
    const batch = packages.slice(i, i + MAX_BATCH);
    let res: Response;
    try {
      res = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
        signal: AbortSignal.timeout(15_000),
      });
    } catch (err) {
      errors.push(`OSV.dev did not respond: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    if (!res.ok) {
      errors.push(`OSV.dev returned HTTP ${res.status} for a batch of ${batch.length} packages`);
      continue;
    }
    const parsed = batchSchema.safeParse(await res.json());
    if (!parsed.success) {
      errors.push("OSV.dev response did not match the expected shape");
      continue;
    }
    // querybatch returns IDs only; resolve full vulnerability details.
    const ids = [...new Set(parsed.data.results.flatMap((r) => (r.vulns ?? []).map((v) => v.id)))];
    const details = new Map<string, z.infer<typeof osvVuln>>();
    await Promise.all(
      ids.map(async (id) => {
        try {
          const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(10_000) });
          if (!r.ok) return;
          const v = osvVuln.safeParse(await r.json());
          if (v.success) details.set(id, v.data);
        } catch {
          // Partial results are still useful; the summary id remains available.
        }
      })
    );
    parsed.data.results.forEach((r, idx) => {
      const pkg = batch[idx];
      const key = `${pkg.ecosystem}:${pkg.name}:${pkg.version}`;
      results[key] = (r.vulns ?? []).map((v) => details.get(v.id) ?? v);
    });
  }
  return json({ results, errors, queried: packages.length, source: "OSV.dev" });
});
