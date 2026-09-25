import type { NextRequest } from "next/server";
import { z } from "zod";
import { extractIndicators } from "@/lib/observables/extract";
import { assertSameOrigin, enforceLimits, handler, json, readJson } from "@/lib/server/api";

const schema = z.object({ text: z.string().max(200_000) });

/** Pulls investigable indicators out of free text. Pure parsing — nothing is contacted. */
export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  await enforceLimits(req, [{ name: "extract", limit: 60, windowSeconds: 60, scope: "client" }]);
  const { text } = await readJson(req, schema, 256 * 1024);
  return json({ indicators: extractIndicators(text) });
});
