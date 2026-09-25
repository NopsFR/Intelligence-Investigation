import type { NextRequest } from "next/server";
import { iocsToCsv, iocsToStix, listIocs } from "@/lib/db/ioc";
import { ApiError, handler } from "@/lib/server/api";
import { observableTypeSchema } from "@/lib/server/schemas";

export const GET = handler(async (req: NextRequest) => {
  const sp = req.nextUrl.searchParams;
  const type = sp.get("type") ? observableTypeSchema.parse(sp.get("type")) : undefined;
  const items = await listIocs({ q: sp.get("q")?.slice(0, 200) || undefined, type, tag: sp.get("tag")?.slice(0, 40) || undefined, limit: 2000 });
  const format = sp.get("format") ?? "csv";
  const stamp = new Date().toISOString().slice(0, 10);
  const file = (body: string, type: string, ext: string) =>
    new Response(body, { headers: { "content-type": `${type}; charset=utf-8`, "content-disposition": `attachment; filename="nops-iocs-${stamp}.${ext}"`, "cache-control": "no-store" } });
  if (format === "csv") return file(iocsToCsv(items), "text/csv", "csv");
  if (format === "json") return file(JSON.stringify({ exportedAt: new Date().toISOString(), items }, null, 2), "application/json", "json");
  if (format === "stix") return file(JSON.stringify(await iocsToStix(items), null, 2), "application/stix+json", "stix.json");
  throw new ApiError(400, "invalid-format", "Format must be csv, json or stix.");
});
