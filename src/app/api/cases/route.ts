import type { NextRequest } from "next/server";
import { createCase, listCases } from "@/lib/db/cases";
import { assertSameOrigin, handler, json, readJson, requireOperator } from "@/lib/server/api";
import { caseCreateSchema } from "@/lib/server/schemas";

export const GET = handler(async (req: NextRequest) => {
  const sp = req.nextUrl.searchParams;
  const status = sp.get("status");
  const items = await listCases({ status: status === "OPEN" || status === "CLOSED" || status === "ARCHIVED" ? status : undefined, q: sp.get("q")?.slice(0, 200) || undefined });
  return json({ items });
});

export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  await requireOperator("Creating a case");
  const body = await readJson(req, caseCreateSchema, 64 * 1024);
  const record = await createCase(body);
  return json(record, { status: 201 });
});
