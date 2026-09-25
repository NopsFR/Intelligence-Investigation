import type { NormalizedFinding } from "@/lib/core/types";

export type CheckStatus = "pass" | "warn" | "fail" | "info";

export interface HeaderCheck {
  id: string;
  header: string;
  status: CheckStatus;
  value?: string;
  note: string;
}

export interface HeaderAnalysis {
  checks: HeaderCheck[];
  findings: NormalizedFinding[];
}

type HeaderBag = Record<string, string | string[] | undefined>;

function get(headers: HeaderBag, name: string): string | undefined {
  const v = headers[name.toLowerCase()];
  return Array.isArray(v) ? v.join(", ") : v;
}

export function parseCsp(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1));
  }
  return directives;
}

function analyzeCsp(csp: string): { issues: string[]; hasFrameAncestors: boolean } {
  const d = parseCsp(csp);
  const issues: string[] = [];
  const script = d.get("script-src") ?? d.get("default-src");
  if (!script) issues.push("no script-src or default-src directive, so scripts are unrestricted");
  else {
    const hasNonceOrHash = script.some((s) => /^'(nonce|sha256|sha384|sha512)-/.test(s));
    const strictDynamic = script.includes("'strict-dynamic'");
    if (script.includes("'unsafe-inline'") && !hasNonceOrHash && !strictDynamic) issues.push("script sources allow 'unsafe-inline'");
    if (script.includes("'unsafe-eval'")) issues.push("script sources allow 'unsafe-eval'");
    if (!strictDynamic && script.some((s) => s === "*" || s === "https:" || s === "http:" || s === "data:")) issues.push(`script sources include a broad scheme or wildcard (${script.filter((s) => ["*", "https:", "http:", "data:"].includes(s)).join(" ")})`);
  }
  if (!d.has("object-src") && !(d.get("default-src") ?? []).includes("'none'")) issues.push("object-src is not restricted");
  if (!d.has("base-uri")) issues.push("base-uri is not set");
  return { issues, hasFrameAncestors: d.has("frame-ancestors") };
}

/**
 * Evaluates security-relevant response headers. Only call this for a response
 * that was actually received — absence here means "not present", never
 * "unable to retrieve".
 */
export function analyzeSecurityHeaders(headers: HeaderBag, options: { https: boolean; host: string; setCookies?: string[] }): HeaderAnalysis {
  const checks: HeaderCheck[] = [];
  const findings: NormalizedFinding[] = [];
  const optional: string[] = [];

  // HSTS
  const hsts = get(headers, "strict-transport-security");
  if (options.https) {
    if (!hsts) {
      checks.push({ id: "hsts", header: "Strict-Transport-Security", status: "fail", note: "Not present" });
      findings.push({
        rule: "headers.hsts-missing",
        severity: "LOW",
        category: "headers",
        title: "HSTS not enabled",
        description: `${options.host} does not send a Strict-Transport-Security header.`,
        rationale: "Without HSTS, a user's first plain-HTTP request can be intercepted and downgraded before the HTTPS redirect happens.",
        evidence: "Response headers did not include Strict-Transport-Security.",
        remediation: "Send Strict-Transport-Security: max-age=31536000; includeSubDomains",
      });
    } else {
      const maxAge = Number(hsts.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
      const sub = /includesubdomains/i.test(hsts);
      const preload = /preload/i.test(hsts);
      const short = maxAge < 15_552_000;
      checks.push({ id: "hsts", header: "Strict-Transport-Security", status: short ? "warn" : "pass", value: hsts, note: `max-age ${Math.round(maxAge / 86400)} days${sub ? ", includeSubDomains" : ""}${preload ? ", preload" : ""}` });
      if (short) {
        findings.push({
          rule: "headers.hsts-short",
          severity: "INFO",
          category: "headers",
          title: `HSTS max-age is only ${Math.round(maxAge / 86400)} days`,
          description: "A max-age under 180 days lets the protection lapse for infrequent visitors.",
          evidence: `Strict-Transport-Security: ${hsts}`,
        });
      }
    }
  }

  // CSP
  const csp = get(headers, "content-security-policy");
  const cspReportOnly = get(headers, "content-security-policy-report-only");
  let frameAncestors = false;
  if (!csp) {
    checks.push({ id: "csp", header: "Content-Security-Policy", status: cspReportOnly ? "warn" : "fail", note: cspReportOnly ? "Report-only policy (not enforced)" : "Not present", value: cspReportOnly });
    findings.push({
      rule: "headers.csp-missing",
      severity: "LOW",
      category: "headers",
      title: cspReportOnly ? "Content Security Policy is report-only" : "No Content Security Policy",
      description: cspReportOnly ? "A CSP is deployed in report-only mode, so violations are logged but not blocked." : `${options.host} does not send a Content-Security-Policy header.`,
      rationale: "CSP is the primary browser-side mitigation against cross-site scripting and content injection.",
      evidence: cspReportOnly ? `Content-Security-Policy-Report-Only: ${cspReportOnly.slice(0, 160)}` : "Response headers did not include Content-Security-Policy.",
    });
  } else {
    const { issues, hasFrameAncestors } = analyzeCsp(csp);
    frameAncestors = hasFrameAncestors;
    checks.push({ id: "csp", header: "Content-Security-Policy", status: issues.length ? "warn" : "pass", value: csp, note: issues.length ? issues.join("; ") : "Restrictive policy" });
    if (issues.some((i) => i.includes("unsafe-inline") || i.includes("wildcard") || i.includes("unrestricted"))) {
      findings.push({
        rule: "headers.csp-weak",
        severity: "LOW",
        category: "headers",
        title: "Content Security Policy does not restrict scripts effectively",
        description: `The policy ${issues.join("; ")}.`,
        rationale: "A CSP that permits inline or arbitrary-origin scripts gives little protection against XSS.",
        evidence: `Content-Security-Policy: ${csp.slice(0, 200)}${csp.length > 200 ? "…" : ""}`,
      });
    }
  }

  // Framing
  const xfo = get(headers, "x-frame-options");
  if (xfo || frameAncestors) {
    checks.push({ id: "framing", header: "X-Frame-Options / frame-ancestors", status: "pass", value: xfo ?? "CSP frame-ancestors", note: "Framing restricted" });
  } else {
    checks.push({ id: "framing", header: "X-Frame-Options / frame-ancestors", status: "fail", note: "Not present" });
    findings.push({
      rule: "headers.clickjacking",
      severity: "LOW",
      category: "headers",
      title: "No clickjacking protection",
      description: "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
      rationale: "Pages that can be framed by any site can be overlaid with deceptive UI (clickjacking).",
      evidence: "Response headers did not include X-Frame-Options or CSP frame-ancestors.",
      remediation: "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).",
    });
  }

  const nosniff = get(headers, "x-content-type-options");
  checks.push({ id: "nosniff", header: "X-Content-Type-Options", status: nosniff?.toLowerCase().includes("nosniff") ? "pass" : "warn", value: nosniff, note: nosniff ? nosniff : "Not present" });
  if (!nosniff?.toLowerCase().includes("nosniff")) optional.push("X-Content-Type-Options: nosniff");

  for (const [id, name] of [
    ["referrer", "Referrer-Policy"],
    ["permissions", "Permissions-Policy"],
    ["coop", "Cross-Origin-Opener-Policy"],
    ["corp", "Cross-Origin-Resource-Policy"],
  ] as const) {
    const v = get(headers, name);
    checks.push({ id, header: name, status: v ? "pass" : "info", value: v, note: v ?? "Not present" });
    if (!v && (id === "referrer" || id === "permissions")) optional.push(name);
  }
  if (optional.length) {
    findings.push({
      rule: "headers.optional-missing",
      severity: "INFO",
      category: "headers",
      title: `Hardening headers absent: ${optional.join(", ")}`,
      description: "These headers are defence-in-depth rather than primary controls.",
      evidence: `Not present in the response from ${options.host}.`,
    });
  }

  // CORS
  const acao = get(headers, "access-control-allow-origin");
  const acac = get(headers, "access-control-allow-credentials");
  if (acao) {
    const dangerous = acao.trim() === "*" && acac?.toLowerCase() === "true";
    checks.push({ id: "cors", header: "Access-Control-Allow-Origin", status: dangerous ? "fail" : acao.trim() === "*" ? "info" : "pass", value: acao, note: dangerous ? "Wildcard origin with credentials" : acao.trim() === "*" ? "Any origin may read responses" : "Specific origin" });
    if (dangerous) {
      findings.push({
        rule: "headers.cors-wildcard-credentials",
        severity: "MEDIUM",
        category: "headers",
        title: "CORS allows any origin with credentials",
        description: "The response combines Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
        rationale: "Browsers reject this combination, but it signals a CORS configuration that may reflect arbitrary origins elsewhere.",
        evidence: `ACAO: ${acao}; ACAC: ${acac}`,
      });
    }
  }

  // Version disclosure
  const disclosure = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
    .map((h) => [h, get(headers, h)] as const)
    .filter(([, v]) => v && /\d/.test(v));
  if (disclosure.length) {
    checks.push({ id: "disclosure", header: "Server / X-Powered-By", status: "info", value: disclosure.map(([h, v]) => `${h}: ${v}`).join("; "), note: "Software versions disclosed" });
    findings.push({
      rule: "headers.version-disclosure",
      severity: "INFO",
      category: "headers",
      title: "Server software version disclosed",
      description: `Headers reveal ${disclosure.map(([h, v]) => `${h}: ${v}`).join(", ")}.`,
      rationale: "Version strings help attackers match the server to known vulnerabilities without probing.",
      evidence: disclosure.map(([h, v]) => `${h}: ${v}`).join("; "),
    });
  }

  // Cookies
  const cookies = options.setCookies ?? [];
  if (cookies.length) {
    const problems: string[] = [];
    for (const c of cookies) {
      const name = c.split("=")[0].trim();
      const attrs = c.toLowerCase();
      const missing = [options.https && !attrs.includes("secure") && "Secure", !attrs.includes("httponly") && "HttpOnly", !attrs.includes("samesite") && "SameSite"].filter(Boolean);
      if (missing.length) problems.push(`${name} (missing ${missing.join(", ")})`);
    }
    checks.push({ id: "cookies", header: "Set-Cookie", status: problems.length ? "warn" : "pass", value: `${cookies.length} cookie(s)`, note: problems.length ? problems.join("; ") : "Secure, HttpOnly and SameSite set" });
    const insecure = problems.filter((p) => p.includes("Secure"));
    if (insecure.length) {
      findings.push({
        rule: "headers.cookie-not-secure",
        severity: "LOW",
        category: "headers",
        title: `${insecure.length} cookie(s) set without the Secure flag`,
        description: `Cookies without Secure can be sent over plain HTTP: ${insecure.join("; ")}.`,
        rationale: "If a session cookie leaks over HTTP it can be hijacked by anyone on the network path.",
        evidence: insecure.join("; "),
      });
    }
  }

  return { checks, findings };
}

export function extractTitle(html: string): string | undefined {
  const m = html.match(/<title[^>]*>([\s\S]{0,400}?)<\/title>/i);
  if (!m) return undefined;
  return m[1]
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 200) || undefined;
}
