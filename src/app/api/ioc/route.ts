import type { NextRequest } from "next/server";
import { detectAs } from "@/lib/observables/detect";
import { addIocs, deleteIocs, listIocs } from "@/lib/db/ioc";
import { ApiError, assertSameOrigin, handler, json, readJson, requireOperator } from "@/lib/server/api";
import { iocCreateSchema, iocDeleteSchema, observableTypeSchema } from "@/lib/server/schemas";

export const GET = handler(async (req: NextRequest) => {
  const sp = req.nextUrl.searchParams;
  const type = sp.get("type") ? observableTypeSchema.parse(sp.get("type")) : undefined;
  return json({ items: await listIocs({ q: sp.get("q")?.slice(0, 200) || undefined, type, tag: sp.get("tag")?.slice(0, 40) || undefined }) });
});

export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  await requireOperator("Editing the IOC library");
  const body = await readJson(req, iocCreateSchema, 512 * 1024);
  const rejected: string[] = [];
  const entries = body.entries.flatMap((e) => {
    const d = detectAs(e.value, e.type);
    if (!d) {
      rejected.push(e.value.slice(0, 100));
      return [];
    }
    return [{ value: d.normalized, type: d.type, tags: e.tags, notes: e.notes, source: body.source, investigationId: e.investigationId }];
  });
  if (!entries.length) throw new ApiError(422, "no-valid-indicators", "None of the submitted values is a recognised observable.");
  const result = await addIocs(entries);
  return json({ ...result, rejected }, { status: 201 });
});

export const DELETE = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  await requireOperator("Editing the IOC library");
  const { ids } = await readJson(req, iocDeleteSchema);
  return json({ deleted: await deleteIocs(ids) });
});
