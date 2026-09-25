import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db/client";
import { ApiError, handler, json } from "@/lib/server/api";
import { idSchema } from "@/lib/server/schemas";

type Ctx = { params: Promise<{ id: string }> };

/** Stored (sanitised) raw provider payload, loaded on demand to keep the main record small. */
export const GET = handler(async (req: NextRequest, { params }: Ctx) => {
  const id = idSchema.parse((await params).id);
  const provider = req.nextUrl.searchParams.get("provider") ?? "";
  if (!/^[a-z0-9-]{2,40}$/.test(provider)) throw new ApiError(400, "invalid-provider", "Specify a provider id.");
  const row = await prisma.providerResult.findUnique({ where: { investigationId_provider: { investigationId: id, provider } }, select: { raw: true, diagnostics: true, retrievedAt: true, status: true } });
  if (!row) throw new ApiError(404, "not-found", "No result from that provider in this investigation.");
  return json({ provider, status: row.status, retrievedAt: row.retrievedAt.toISOString(), diagnostics: row.diagnostics, raw: row.raw });
});
