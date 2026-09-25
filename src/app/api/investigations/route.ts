import { after, type NextRequest } from "next/server";
import { detectAs } from "@/lib/observables/detect";
import { createInvestigation, runInvestigation } from "@/lib/engine/investigate";
import { listInvestigations } from "@/lib/db/investigations";
import { ApiError, assertSameOrigin, enforceLimits, handler, json, readJson, requireOperator } from "@/lib/server/api";
import { log } from "@/lib/server/log";
import { investigateSchema, listSchema } from "@/lib/server/schemas";

export const maxDuration = 120;

export const GET = handler(async (req: NextRequest) => {
  const params = listSchema.parse(Object.fromEntries(req.nextUrl.searchParams));
  return json(await listInvestigations(params as Parameters<typeof listInvestigations>[0]));
});

export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  const body = await readJson(req, investigateSchema);
  const detected = detectAs(body.observable, body.type);
  if (!detected) {
    throw new ApiError(422, "unrecognised-observable", body.type ? `“${body.observable.slice(0, 80)}” is not a valid ${body.type}.` : `“${body.observable.slice(0, 80)}” is not a recognised observable type.`);
  }
  if (body.mode === "DEEP") await requireOperator("Deep investigation (it contacts the target directly)");
  await enforceLimits(req, [
    { name: "investigate", limit: 12, windowSeconds: 60, scope: "client" },
    { name: "investigate", limit: 400, windowSeconds: 3600, scope: "global" },
  ]);

  const { id, reused } = await createInvestigation({ observable: body.observable.trim(), normalized: detected.normalized, type: detected.type, mode: body.mode, fresh: body.fresh });
  if (!reused) {
    after(async () => {
      try {
        await runInvestigation(id);
      } catch (err) {
        log("error", "investigation failed", { id, error: (err as Error).message });
      }
    });
  }
  return json({ id, reused, detected: { type: detected.type, normalized: detected.normalized, notes: detected.notes } }, { status: reused ? 200 : 202 });
});
