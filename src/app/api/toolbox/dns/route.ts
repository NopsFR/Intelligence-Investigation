import type { NextRequest } from "next/server";
import { query, RESOLVERS } from "@/lib/dns/resolvers";
import { normalizeHostname } from "@/lib/observables/detect";
import { reverseDnsName } from "@/lib/observables/ip";
import { ApiError, enforceLimits, handler, json } from "@/lib/server/api";
import { dnsToolSchema } from "@/lib/server/schemas";

/** Live DNS lookup against a chosen public DoH resolver. */
export const GET = handler(async (req: NextRequest) => {
  const params = dnsToolSchema.parse(Object.fromEntries(req.nextUrl.searchParams));
  await enforceLimits(req, [{ name: "dns-tool", limit: 60, windowSeconds: 60, scope: "client" }]);
  const name = params.type === "PTR" ? reverseDnsName(params.name) ?? params.name : normalizeHostname(params.name.replace(/\.$/, "")) ?? (/^[a-z0-9_.-]+$/i.test(params.name) ? params.name.toLowerCase() : null);
  if (!name) throw new ApiError(422, "invalid-name", "Enter a valid DNS name (or an IP address for PTR).");
  const res = await query(params.resolver, name, params.type, AbortSignal.timeout(8000)).catch((err: Error) => {
    throw new ApiError(502, "resolver-error", `${RESOLVERS[params.resolver].name} did not answer: ${err.message}`);
  });
  return json({ query: { name, type: params.type }, ...res, resolver: { id: params.resolver, ...RESOLVERS[params.resolver] } });
});
