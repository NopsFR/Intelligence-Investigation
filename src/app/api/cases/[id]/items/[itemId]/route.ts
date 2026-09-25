import type { NextRequest } from "next/server";
import { deleteCaseItem, getCase } from "@/lib/db/cases";
import { ApiError, assertSameOrigin, handler, json, requireOperator } from "@/lib/server/api";
import { idSchema } from "@/lib/server/schemas";

export const DELETE = handler(async (req: NextRequest, { params }: { params: Promise<{ id: string; itemId: string }> }) => {
  assertSameOrigin(req);
  await requireOperator("Editing a case");
  const { id, itemId } = await params;
  const caseId = idSchema.parse(id);
  const existing = await getCase(caseId);
  if (!existing) throw new ApiError(404, "not-found", "No case with this id.");
  await deleteCaseItem(caseId, idSchema.parse(itemId));
  return json({ deleted: true });
});
