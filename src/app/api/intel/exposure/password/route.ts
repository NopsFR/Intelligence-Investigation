import type { NextRequest } from "next/server";
import { providerRequest } from "@/lib/net/provider-fetch";
import { ApiError, assertSameOrigin, enforceLimits, handler, json, readJson } from "@/lib/server/api";
import { exposurePasswordSchema } from "@/lib/server/schemas";

/**
 * Pwned Passwords k-anonymity range query. The browser hashes the password
 * with SHA-1 and sends only the first 5 hex characters; this route forwards
 * that prefix to the Pwned Passwords API (Add-Padding for uniform response
 * sizes) and returns every suffix:count pair for the client to match
 * locally. The full hash, and the password itself, never reach this server
 * or the upstream API.
 */
export const POST = handler(async (req: NextRequest) => {
  assertSameOrigin(req);
  const { prefix } = await readJson(req, exposurePasswordSchema, 1024);
  await enforceLimits(req, [{ name: "exposure-password", limit: 30, windowSeconds: 60, scope: "client" }]);
  let res;
  try {
    res = await providerRequest(`https://api.pwnedpasswords.com/range/${prefix.toUpperCase()}`, { timeoutMs: 10_000, maxBytes: 2 * 1024 * 1024, headers: { "Add-Padding": "true" } });
  } catch (err) {
    throw new ApiError(502, "provider-unavailable", `Pwned Passwords is unavailable: ${err instanceof Error ? err.message : String(err)}`);
  }
  const suffixes: { suffix: string; count: number }[] = [];
  for (const line of res.text.split("\r\n")) {
    const [suffix, count] = line.split(":");
    if (suffix && count && Number(count) > 0) suffixes.push({ suffix, count: Number(count) });
  }
  return json({ prefix: prefix.toUpperCase(), suffixes, source: "Have I Been Pwned — Pwned Passwords (k-anonymity)" });
});
