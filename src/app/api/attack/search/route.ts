import type { NextRequest } from "next/server";
import { loadAttack, searchAttack } from "@/lib/intel/attack";
import { handler, json } from "@/lib/server/api";

export const GET = handler(async (req: NextRequest) => {
  const q = (req.nextUrl.searchParams.get("q") ?? "").slice(0, 100);
  const index = await loadAttack();
  return json({ results: searchAttack(index, q, 30), version: index.meta.version });
});
