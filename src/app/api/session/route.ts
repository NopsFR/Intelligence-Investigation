import type { NextRequest } from "next/server";
import { cookies } from "next/headers";
import { ApiError, assertSameOrigin, enforceLimits, handler, isOperator, json, readJson } from "@/lib/server/api";
import { log } from "@/lib/server/log";
import { sessionSchema } from "@/lib/server/schemas";
import { SESSION_COOKIE, SESSION_TTL_SECONDS, issueSession, operatorConfigured, sessionExpiry, verifyToken } from "@/lib/server/session";

export const GET = handler(async () => {
  const jar = await cookies();
  const operator = await isOperator();
  return json({ operator, configured: operatorConfigured(), privateMode: process.env.NOPS_PRIVATE === "1", expiresAt: operator ? sessionExpiry(jar.get(SESSION_COOKIE)?.value)?.toISOString() : undefined });
});

export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  await enforceLimits(req, [{ name: "unlock", limit: 10, windowSeconds: 900, scope: "client" }]);
  if (!operatorConfigured()) throw new ApiError(409, "not-configured", "No operator token is configured on this deployment (NOPS_ADMIN_TOKEN).");
  const { token } = await readJson(req, sessionSchema);
  if (!verifyToken(token)) {
    log("warn", "operator unlock failed");
    throw new ApiError(401, "invalid-token", "That operator token is not valid.");
  }
  const value = issueSession()!;
  const jar = await cookies();
  jar.set(SESSION_COOKIE, value, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/", maxAge: SESSION_TTL_SECONDS });
  return json({ operator: true, expiresAt: sessionExpiry(value)?.toISOString() });
});

export const DELETE = handler(async (req: NextRequest) => {
  assertSameOrigin(req, { requireJson: false });
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
  return json({ operator: false });
});
