import type { NextRequest } from "next/server";
import { getInvestigation } from "@/lib/db/investigations";
import { PROVIDERS } from "@/lib/providers/registry";
import { findingsCsv, reportMarkdown } from "@/lib/report/export";
import { ApiError, handler } from "@/lib/server/api";
import { idSchema } from "@/lib/server/schemas";

type Ctx = { params: Promise<{ id: string }> };

const names = Object.fromEntries(PROVIDERS.map((p) => [p.id, p.name]));

export const GET = handler(async (req: NextRequest, { params }: Ctx) => {
  const id = idSchema.parse((await params).id);
  const inv = await getInvestigation(id);
  if (!inv) throw new ApiError(404, "not-found", "Investigation not found.");
  const format = req.nextUrl.searchParams.get("format") ?? "json";
  const base = `nops-${inv.observableType.toLowerCase()}-${inv.normalizedObservable.replace(/[^a-z0-9.-]+/gi, "_").slice(0, 60)}-${inv.createdAt.slice(0, 10)}`;
  const download = (body: string, type: string, ext: string) =>
    new Response(body, { headers: { "content-type": `${type}; charset=utf-8`, "content-disposition": `attachment; filename="${base}.${ext}"`, "cache-control": "no-store", "x-content-type-options": "nosniff" } });
  switch (format) {
    case "json":
      return download(JSON.stringify({ format: "nops-investigation", version: 2, exportedAt: new Date().toISOString(), investigation: inv }, null, 2), "application/json", "json");
    case "csv":
      return download(findingsCsv(inv, names), "text/csv", "csv");
    case "md":
      return download(reportMarkdown(inv, names), "text/markdown", "md");
    default:
      throw new ApiError(400, "invalid-format", "Format must be json, csv or md.");
  }
});
