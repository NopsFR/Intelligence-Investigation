import type { NextRequest } from "next/server";
import { addCaseItem, getCase } from "@/lib/db/cases";
import { ApiError, assertSameOrigin, handler, json, readJson, requireOperator } from "@/lib/server/api";
import { caseItemCreateSchema, idSchema } from "@/lib/server/schemas";

export const POST = handler(async (req: NextRequest, { params }: { params: Promise<{ id: string }> }) => {
  assertSameOrigin(req);
  await requireOperator("Editing a case");
  const id = idSchema.parse((await params).id);
  const existing = await getCase(id);
  if (!existing) throw new ApiError(404, "not-found", "No case with this id.");
  const body = await readJson(req, caseItemCreateSchema, 128 * 1024);
  const item = await addCaseItem(id, body.kind, body.data);
  return json(item, { status: 201 });
});
