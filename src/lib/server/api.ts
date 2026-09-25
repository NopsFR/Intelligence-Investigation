import "server-only";
import { createHash } from "node:crypto";
import { cookies } from "next/headers";
import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { consumeBucket } from "@/lib/db/stores";
import { log } from "./log";
import { SESSION_COOKIE, operatorConfigured, operatorOpenByDefault, verifySession } from "./session";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly headers?: Record<string, string>
  ) {
    super(message);
  }
}

export function json<T>(data: T, init?: ResponseInit): NextResponse {
  return NextResponse.json(data, { ...init, headers: { "cache-control": "no-store", ...(init?.headers ?? {}) } });
}

/** Wraps a route handler with uniform error handling; internals never leak to the client. */
export function handler<Ctx>(fn: (req: NextRequest, ctx: Ctx) => Promise<Response>) {
  return async (req: NextRequest, ctx: Ctx): Promise<Response> => {
    try {
      return await fn(req, ctx);
    } catch (err) {
      if (err instanceof ApiError) return json({ error: { code: err.code, message: err.message } }, { status: err.status, headers: err.headers });
      if (err instanceof z.ZodError) {
        return json({ error: { code: "invalid-request", message: err.issues.map((i) => `${i.path.join(".") || "body"}: ${i.message}`).join("; ") } }, { status: 400 });
      }
      log("error", "unhandled API error", { path: req.nextUrl.pathname, error: (err as Error)?.message });
      return json({ error: { code: "internal-error", message: "The request could not be completed." } }, { status: 500 });
    }
  };
}

/**
 * CSRF defence for state-changing requests: the browser must say the request
 * is same-origin (Sec-Fetch-Site / Origin), and bodies must be JSON, which a
 * cross-site form cannot send without a CORS preflight.
 */
export function assertSameOrigin(req: NextRequest, { requireJson = true } = {}) {
  const site = req.headers.get("sec-fetch-site");
  const origin = req.headers.get("origin");
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  if (site && site !== "same-origin" && site !== "none") throw new ApiError(403, "cross-site", "Cross-site requests are not accepted.");
  if (origin) {
    let originHost: string;
    try {
      originHost = new URL(origin).host;
    } catch {
      throw new ApiError(403, "bad-origin", "Invalid Origin header.");
    }
    if (host && originHost !== host) throw new ApiError(403, "cross-origin", "Cross-origin requests are not accepted.");
  }
  if (requireJson && !(req.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    throw new ApiError(415, "unsupported-media-type", "Send the request body as application/json.");
  }
}

export async function readJson<T>(req: NextRequest, schema: z.ZodType<T>, maxBytes = 64 * 1024): Promise<T> {
  const length = Number(req.headers.get("content-length") ?? 0);
  if (length > maxBytes) throw new ApiError(413, "payload-too-large", `Request body exceeds ${maxBytes} bytes.`);
  const text = await req.text();
  if (text.length > maxBytes) throw new ApiError(413, "payload-too-large", `Request body exceeds ${maxBytes} bytes.`);
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    throw new ApiError(400, "invalid-json", "Request body is not valid JSON.");
  }
  return schema.parse(body);
}

/** Salted hash of the client address: rate-limit keys never store raw IPs. */
export function clientKey(req: NextRequest): string {
  const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const ip = forwarded || req.headers.get("x-real-ip") || "unknown";
  return createHash("sha256").update(`nops:${process.env.NOPS_SESSION_SECRET ?? ""}:${ip}`).digest("hex").slice(0, 24);
}

export interface LimitSpec {
  name: string;
  limit: number;
  windowSeconds: number;
  scope: "client" | "global";
}

export async function enforceLimits(req: NextRequest, specs: LimitSpec[]) {
  for (const spec of specs) {
    const key = spec.scope === "global" ? `api:${spec.name}:global` : `api:${spec.name}:${clientKey(req)}`;
    let result;
    try {
      result = await consumeBucket(key, spec.limit, spec.windowSeconds);
    } catch (err) {
      // Fail open on a database hiccup rather than locking every user out.
      log("warn", "rate limiter unavailable", { error: (err as Error).message });
      return;
    }
    if (!result.allowed) {
      const retry = Math.max(1, Math.ceil((result.resetAt.getTime() - Date.now()) / 1000));
      throw new ApiError(429, "rate-limited", `Too many requests (${spec.limit} per ${spec.windowSeconds >= 3600 ? `${spec.windowSeconds / 3600}h` : `${spec.windowSeconds}s`}${spec.scope === "global" ? ", instance-wide" : ""}). Try again in ${retry}s.`, {
        "retry-after": String(retry),
      });
    }
  }
}

export async function isOperator(): Promise<boolean> {
  if (operatorOpenByDefault()) return true;
  if (!operatorConfigured()) return false;
  const jar = await cookies();
  return verifySession(jar.get(SESSION_COOKIE)?.value);
}

export async function requireOperator(action: string) {
  if (await isOperator()) return;
  throw new ApiError(
    401,
    "operator-required",
    operatorConfigured()
      ? `${action} requires an operator session. Unlock it under Settings → Security.`
      : `${action} is disabled: no operator token (NOPS_ADMIN_TOKEN) is configured on this deployment.`
  );
}
