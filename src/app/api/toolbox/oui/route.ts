import type { NextRequest } from "next/server";
import { lookupOui } from "@/lib/intel/feeds";
import { ApiError, enforceLimits, handler, json } from "@/lib/server/api";

export const GET = handler(async (req: NextRequest) => {
  const mac = req.nextUrl.searchParams.get("mac")?.trim() ?? "";
  if (!/^[0-9a-fA-F:.\-]{6,}$/.test(mac)) throw new ApiError(422, "invalid-mac", "Enter a MAC address or OUI prefix, e.g. 00:1A:2B:...");
  await enforceLimits(req, [{ name: "toolbox-oui", limit: 60, windowSeconds: 60, scope: "client" }]);
  let entry;
  try {
    entry = await lookupOui(mac);
  } catch (err) {
    throw new ApiError(502, "provider-unavailable", `IEEE OUI registry is unavailable: ${err instanceof Error ? err.message : String(err)}`);
  }
  return json({ mac, found: !!entry, prefix: entry?.prefix, vendor: entry?.vendor });
});
