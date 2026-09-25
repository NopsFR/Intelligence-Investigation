import type { NextRequest } from "next/server";
import { OBSERVABLE_LABELS } from "@/lib/core/types";
import { detectObservable } from "@/lib/observables/detect";
import { handler, json } from "@/lib/server/api";

export const GET = handler(async (req: NextRequest) => {
  const q = (req.nextUrl.searchParams.get("q") ?? "").slice(0, 2048);
  const d = detectObservable(q);
  return json(d ? { type: d.type, label: OBSERVABLE_LABELS[d.type], normalized: d.normalized, alternatives: d.alternatives, notes: d.notes } : { type: null });
});
