import type { NextRequest } from "next/server";
import { deleteInvestigation, getInvestigation, investigationHistory } from "@/lib/db/investigations";
import { ApiError, assertSameOrigin, handler, json, requireOperator } from "@/lib/server/api";
import { idSchema } from "@/lib/server/schemas";

type Ctx = { params: Promise<{ id: string }> };

export const GET = handler(async (req: NextRequest, { params }: Ctx) => {
  const id = idSchema.parse((await params).id);
  const record = await getInvestigation(id);
  if (!record) throw new ApiError(404, "not-found", "Investigation not found.");
  const history = req.nextUrl.searchParams.get("history") === "1" ? await investigationHistory(record.normalizedObservable, record.observableType, record.id) : undefined;
  return json({ investigation: record, history });
});

export const DELETE = handler(async (req: NextRequest, { params }: Ctx) => {
  assertSameOrigin(req, { requireJson: false });
  await requireOperator("Deleting investigations");
  const id = idSchema.parse((await params).id);
  if (!(await deleteInvestigation(id))) throw new ApiError(404, "not-found", "Investigation not found.");
  return json({ deleted: id });
});
