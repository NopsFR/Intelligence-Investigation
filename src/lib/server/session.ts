import { createHash, createHmac, timingSafeEqual } from "node:crypto";

// Operator session: a single shared operator token (NOPS_ADMIN_TOKEN) exchanged
// for an HMAC-signed, HttpOnly cookie. No token material ever reaches the client.

export const SESSION_COOKIE = "nops_session";
export const SESSION_TTL_SECONDS = 12 * 60 * 60;

function adminToken(): string | undefined {
  return process.env.NOPS_ADMIN_TOKEN?.trim() || undefined;
}

function signingKey(): Buffer | null {
  const secret = process.env.NOPS_SESSION_SECRET?.trim();
  if (secret) return createHash("sha256").update(secret).digest();
  const token = adminToken();
  // Derived key: rotating the admin token also invalidates every session.
  return token ? createHash("sha256").update(`nops-session:${token}`).digest() : null;
}

export function operatorConfigured(): boolean {
  return Boolean(adminToken());
}

/** Without a configured token, operator actions are open in development and closed in production. */
export function operatorOpenByDefault(): boolean {
  return !operatorConfigured() && process.env.NODE_ENV !== "production";
}

export function verifyToken(candidate: string): boolean {
  const token = adminToken();
  if (!token || !candidate) return false;
  const a = createHash("sha256").update(candidate).digest();
  const b = createHash("sha256").update(token).digest();
  return timingSafeEqual(a, b);
}

export function issueSession(now = Date.now()): string | null {
  const key = signingKey();
  if (!key) return null;
  const expires = Math.floor(now / 1000) + SESSION_TTL_SECONDS;
  const payload = `v1.${expires}`;
  const mac = createHmac("sha256", key).update(payload).digest("base64url");
  return `${payload}.${mac}`;
}

export function verifySession(value: string | undefined, now = Date.now()): boolean {
  const key = signingKey();
  if (!key || !value) return false;
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return false;
  const expires = Number(parts[1]);
  if (!Number.isFinite(expires) || expires * 1000 < now) return false;
  const expected = createHmac("sha256", key).update(`${parts[0]}.${parts[1]}`).digest();
  let given: Buffer;
  try {
    given = Buffer.from(parts[2], "base64url");
  } catch {
    return false;
  }
  return given.length === expected.length && timingSafeEqual(given, expected);
}

export function sessionExpiry(value: string | undefined): Date | null {
  const expires = Number(value?.split(".")[1]);
  return Number.isFinite(expires) ? new Date(expires * 1000) : null;
}
