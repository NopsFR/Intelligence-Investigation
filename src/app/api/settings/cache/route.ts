import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db/client";
import { assertSameOrigin, handler, json, requireOperator } from "@/lib/server/api";

/** Purges provider cache entries: expired only, or everything with ?all=1. */
export const DELETE = handler(async (req: NextRequest) => {
  assertSameOrigin(req, { requireJson: false });
  await requireOperator("Clearing the provider cache");
  const all = req.nextUrl.searchParams.get("all") === "1";
  const res = await prisma.providerCache.deleteMany({ where: all ? {} : { expiresAt: { lte: new Date() } } });
  return json({ deleted: res.count });
});
