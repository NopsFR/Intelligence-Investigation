import type { NextRequest } from "next/server";
import { deleteCase, getCase, updateCase } from "@/lib/db/cases";
import { ApiError, assertSameOrigin, handler, json, readJson, requireOperator } from "@/lib/server/api";
import { casePatchSchema, idSchema } from "@/lib/server/schemas";

export const GET = handler(async (_req: NextRequest, { params }: { params: Promise<{ id: string }> }) => {
  const id = idSchema.parse((await params).id);
  const record = await getCase(id);
  if (!record) throw new ApiError(404, "not-found", "No case with this id.");
  return json(record);
});

export const PATCH = handler(async (req: NextRequest, { params }: { params: Promise<{ id: string }> }) => {
  assertSameOrigin(req);
  await requireOperator("Editing a case");
  const id = idSchema.parse((await params).id);
  const patch = await readJson(req, casePatchSchema, 64 * 1024);
  const existing = await getCase(id);
  if (!existing) throw new ApiError(404, "not-found", "No case with this id.");
  await updateCase(id, patch);
  return json(await getCase(id));
});

export const DELETE = handler(async (req: NextRequest, { params }: { params: Promise<{ id: string }> }) => {
  assertSameOrigin(req);
  await requireOperator("Deleting a case");
  const id = idSchema.parse((await params).id);
  const existing = await getCase(id);
  if (!existing) throw new ApiError(404, "not-found", "No case with this id.");
  await deleteCase(id);
  return json({ deleted: true });
});
