import type { NextRequest } from "next/server";
import { analyzeWebSecurity } from "@/lib/web/analyze";
import { TargetRequestError } from "@/lib/net/target";
import { ApiError, enforceLimits, handler, json, requireOperator } from "@/lib/server/api";
import { webSecuritySchema } from "@/lib/server/schemas";

/**
 * Authorized-URL web security scan: headers, cookies, TLS, CORS, robots.txt,
 * security.txt, sitemap.xml and technology indicators. Contacts the target
 * directly (the same SSRF-safe fetch as a Deep investigation), so it needs
 * an operator session for the same reason Deep mode does.
 */
export const GET = handler(async (req: NextRequest) => {
  await requireOperator("Web security scan (it contacts the target directly)");
  const { url } = webSecuritySchema.parse(Object.fromEntries(req.nextUrl.searchParams));
  await enforceLimits(req, [
    { name: "web-security-scan", limit: 20, windowSeconds: 60, scope: "client" },
    { name: "web-security-scan-global", limit: 200, windowSeconds: 60, scope: "global" },
  ]);
  try {
    const report = await analyzeWebSecurity(url);
    return json(report);
  } catch (err) {
    if (err instanceof TargetRequestError) {
      const status = err.kind === "policy" ? 422 : err.kind === "timeout" ? 504 : 502;
      throw new ApiError(status, `target-${err.kind}`, err.message);
    }
    throw err;
  }
});
