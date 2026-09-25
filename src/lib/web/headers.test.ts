import { describe, expect, it } from "vitest";
import { analyzeSecurityHeaders, extractTitle, parseCsp } from "./headers";

const rules = (h: Record<string, string>, opts: Partial<{ https: boolean; setCookies: string[] }> = {}) =>
  analyzeSecurityHeaders(h, { https: true, host: "example.com", ...opts }).findings.map((f) => f.rule);

describe("security header analysis", () => {
  it("reports missing controls on a bare response", () => {
    expect(rules({})).toEqual(expect.arrayContaining(["headers.hsts-missing", "headers.csp-missing", "headers.clickjacking", "headers.optional-missing"]));
  });

  it("accepts a hardened response", () => {
    const r = rules({
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=()",
    });
    expect(r).toEqual([]);
  });

  it("recognises weak CSP, short HSTS, CORS and version disclosure", () => {
    const r = rules({
      "strict-transport-security": "max-age=86400",
      "content-security-policy": "default-src * 'unsafe-inline'",
      "access-control-allow-origin": "*",
      "access-control-allow-credentials": "true",
      server: "Apache/2.4.49 (Unix)",
    });
    expect(r).toEqual(expect.arrayContaining(["headers.hsts-short", "headers.csp-weak", "headers.cors-wildcard-credentials", "headers.version-disclosure"]));
  });

  it("does not demand HSTS over plain HTTP but flags insecure cookies over HTTPS", () => {
    expect(rules({}, { https: false })).not.toContain("headers.hsts-missing");
    expect(rules({}, { setCookies: ["sid=abc; HttpOnly; SameSite=Lax"] })).toContain("headers.cookie-not-secure");
  });

  it("parses CSP directives and titles", () => {
    expect(parseCsp("script-src 'self'; object-src 'none'").get("object-src")).toEqual(["'none'"]);
    expect(extractTitle("<html><title> Sign in &amp; verify </title>")).toBe("Sign in & verify");
    expect(extractTitle("<html>no title</html>")).toBeUndefined();
  });
});
