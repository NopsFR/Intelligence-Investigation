import type { NextRequest } from "next/server";
import { deleteIocs, updateIoc } from "@/lib/db/ioc";
import { ApiError, assertSameOrigin, handler, json, readJson, requireOperator } from "@/lib/server/api";
import { idSchema, iocPatchSchema } from "@/lib/server/schemas";

type Ctx = { params: Promise<{ id: string }> };

export const PATCH = handler(async (req: NextRequest, { params }: Ctx) => {
  assertSameOrigin(req);
  await requireOperator("Editing the IOC library");
  const id = idSchema.parse((await params).id);
  const patch = await readJson(req, iocPatchSchema);
  try {
    const row = await updateIoc(id, patch);
    return json({ id: row.id });
  } catch {
    throw new ApiError(404, "not-found", "Indicator not found.");
  }
});

export const DELETE = handler(async (req: NextRequest, { params }: Ctx) => {
  assertSameOrigin(req, { requireJson: false });
  await requireOperator("Editing the IOC library");
  const id = idSchema.parse((await params).id);
  if (!(await deleteIocs([id]))) throw new ApiError(404, "not-found", "Indicator not found.");
  return json({ deleted: id });
});
