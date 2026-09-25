import "server-only";
import type { NormalizedFinding, Severity } from "@/lib/core/types";
import { assertTargetUrl, targetRequest, TargetRequestError, type TargetResponse } from "@/lib/net/target";
import { analyzeSecurityHeaders, extractTitle, type HeaderCheck } from "./headers";

// Standalone, authorized-URL web security scan: the same SSRF-safe fetch the
// investigation engine uses, plus robots.txt / security.txt / sitemap.xml,
// a CORS reflection probe, and simple technology indicators. Every check
// reports what was actually observed; nothing here exploits or attacks.

export interface TextResource {
  path: string;
  present: boolean;
  status?: number;
  size?: number;
  excerpt?: string;
  contentType?: string;
}

export interface CorsProbe {
  tested: boolean;
  reflectsOrigin: boolean;
  allowCredentialsWithWildcard: boolean;
  allowOrigin?: string;
  allowCredentials?: string;
}

export interface WebSecurityReport {
  url: string;
  finalUrl: string;
  status: number;
  https: boolean;
  hops: TargetResponse["hops"];
  title?: string;
  server?: string;
  poweredBy?: string;
  tls?: TargetResponse["tls"];
  headers: Record<string, string>;
  setCookies: { raw: string; name: string; secure: boolean; httpOnly: boolean; sameSite?: string }[];
  checks: HeaderCheck[];
  robots: TextResource;
  securityTxt: TextResource & { fields?: Record<string, string[]> };
  sitemap: TextResource & { urlCount?: number };
  cors: CorsProbe;
  technologies: string[];
  findings: NormalizedFinding[];
  bodyTruncated: boolean;
  durationMs: number;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function parseSetCookie(raw: string) {
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue] = parts;
  const name = nameValue.split("=")[0];
  const lower = parts.map((p) => p.toLowerCase());
  const sameSite = parts.find((p) => p.toLowerCase().startsWith("samesite="))?.split("=")[1];
  return { raw, name, secure: lower.includes("secure"), httpOnly: lower.includes("httponly"), sameSite };
}

async function fetchText(base: URL, path: string, maxBytes: number): Promise<TextResource> {
  const url = new URL(path, base).toString();
  try {
    const res = await targetRequest(url, { method: "GET", timeoutMs: 6000, maxBodyBytes: maxBytes, maxRedirects: 2 });
    const contentType = String(res.headers["content-type"] ?? "");
    const looksReal = res.status === 200 && !/text\/html/i.test(contentType.split(";")[0] ?? "") ? true : res.status === 200;
    return { path, present: res.status === 200 && looksReal, status: res.status, size: res.body.length, excerpt: res.body.slice(0, 4000), contentType };
  } catch {
    return { path, present: false };
  }
}

export function parseSecurityTxt(text: string): Record<string, string[]> {
  const fields: Record<string, string[]> = {};
  for (const line of text.split("\n")) {
    const l = line.trim();
    if (!l || l.startsWith("#")) continue;
    const i = l.indexOf(":");
    if (i < 0) continue;
    const key = l.slice(0, i).trim();
    const value = l.slice(i + 1).trim();
    (fields[key] ??= []).push(value);
  }
  return fields;
}

export function detectTechnologies(headers: Record<string, string>, body: string): string[] {
  const tech = new Set<string>();
  const server = headers.server ?? "";
  const xpb = headers["x-powered-by"] ?? "";
  for (const [re, name] of [
    [/nginx/i, "Nginx"],
    [/apache/i, "Apache HTTP Server"],
    [/cloudflare/i, "Cloudflare"],
    [/cloudfront/i, "Amazon CloudFront"],
    [/varnish/i, "Varnish"],
    [/iis/i, "Microsoft IIS"],
    [/express/i, "Express"],
    [/kestrel/i, "ASP.NET Core (Kestrel)"],
  ] as const)
    if (re.test(server) || re.test(xpb)) tech.add(name);
  if (/^php/i.test(xpb) || headers["x-powered-by"]?.toLowerCase().includes("php")) tech.add("PHP");
  if (headers["x-drupal-cache"] || /drupal/i.test(body)) tech.add("Drupal");
  if (/wp-content|wp-includes/i.test(body)) tech.add("WordPress");
  if (/name="generator" content="joomla/i.test(body)) tech.add("Joomla");
  if (/cdn\.shopify\.com|Shopify\.theme/i.test(body)) tech.add("Shopify");
  if (/_next\/static/i.test(body)) tech.add("Next.js");
  if (/data-reactroot|react-dom/i.test(body)) tech.add("React");
  if (/ng-version=/i.test(body)) tech.add("Angular");
  if (/__NUXT__/i.test(body)) tech.add("Nuxt");
  if (/data-turbo|hotwire/i.test(body)) tech.add("Hotwire/Turbo");
  if (headers["cf-ray"]) tech.add("Cloudflare");
  if (headers["x-vercel-id"] || headers["x-vercel-cache"]) tech.add("Vercel");
  if (headers["x-amz-cf-id"]) tech.add("Amazon CloudFront");
  if (headers["x-github-request-id"]) tech.add("GitHub Pages");
  if (headers["x-fastly-request-id"] || headers.via?.includes("fastly")) tech.add("Fastly");
  return [...tech].sort();
}

export async function analyzeWebSecurity(rawUrl: string): Promise<WebSecurityReport> {
  const started = Date.now();
  const base = assertTargetUrl(rawUrl);
  const res = await targetRequest(base.toString(), { method: "GET", timeoutMs: 9000, maxBodyBytes: 1_500_000, maxRedirects: 6 });
  const finalUrl = new URL(res.url);
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v ?? "");

  const analysis = analyzeSecurityHeaders(res.headers as Record<string, string | string[] | undefined>, { https: finalUrl.protocol === "https:", host: finalUrl.hostname, setCookies: res.setCookies });
  const findings = [...analysis.findings];

  const [robotsRes, securityTxtRes, wellKnownSecurityTxtRes, sitemapRes] = await Promise.all([fetchText(finalUrl, "/robots.txt", 200_000), fetchText(finalUrl, "/security.txt", 20_000), fetchText(finalUrl, "/.well-known/security.txt", 20_000), fetchText(finalUrl, "/sitemap.xml", 500_000)]);
  const securityTxtSource = wellKnownSecurityTxtRes.present ? wellKnownSecurityTxtRes : securityTxtRes;
  const securityTxt = { ...securityTxtSource, fields: securityTxtSource.present && securityTxtSource.excerpt ? parseSecurityTxt(securityTxtSource.excerpt) : undefined };
  if (!securityTxt.present) findings.push({ rule: "web.no-security-txt", severity: "INFO", category: "web", title: "No security.txt", description: "Neither /.well-known/security.txt nor /security.txt was found.", rationale: "RFC 9116 security.txt gives researchers a defined way to report vulnerabilities responsibly.", evidence: "404 or non-text response at both locations" });
  else if (!securityTxt.fields?.Contact) findings.push({ rule: "web.security-txt-no-contact", severity: "LOW", category: "web", title: "security.txt has no Contact field", description: "RFC 9116 requires at least one Contact field.", rationale: "Without a contact method, researchers have no defined way to reach the team.", evidence: securityTxt.excerpt?.slice(0, 200) ?? "" });

  const sitemapUrlCount = sitemapRes.present && sitemapRes.excerpt ? (sitemapRes.excerpt.match(/<loc>/g)?.length ?? 0) : undefined;

  // CORS reflection probe: send a foreign Origin and see whether it is reflected.
  let cors: CorsProbe = { tested: false, reflectsOrigin: false, allowCredentialsWithWildcard: false };
  try {
    const probeOrigin = "https://cors-probe.invalid.example";
    const probe = await targetRequest(finalUrl.toString(), { method: "GET", timeoutMs: 6000, maxBodyBytes: 1024, maxRedirects: 1, headers: { origin: probeOrigin } });
    const allowOrigin = String(probe.headers["access-control-allow-origin"] ?? "");
    const allowCredentials = String(probe.headers["access-control-allow-credentials"] ?? "");
    cors = { tested: true, reflectsOrigin: allowOrigin === probeOrigin, allowCredentialsWithWildcard: allowOrigin === "*" && allowCredentials.toLowerCase() === "true", allowOrigin: allowOrigin || undefined, allowCredentials: allowCredentials || undefined };
    if (cors.reflectsOrigin && cors.allowCredentials?.toLowerCase() === "true") {
      findings.push({ rule: "web.cors-reflects-credentialed", severity: "HIGH", category: "web", title: "CORS reflects an arbitrary Origin with credentials allowed", description: `A request with Origin: ${probeOrigin} (which the site cannot know in advance) got that exact value back in Access-Control-Allow-Origin, together with Access-Control-Allow-Credentials: true.`, rationale: "This lets any website read authenticated responses from this origin on a victim's behalf — a direct cross-origin data theft path.", evidence: `Access-Control-Allow-Origin: ${allowOrigin}; Access-Control-Allow-Credentials: ${allowCredentials}` });
    } else if (cors.allowCredentialsWithWildcard) {
      findings.push({ rule: "web.cors-wildcard-credentials", severity: "MEDIUM", category: "web", title: "CORS allows * with credentials", description: "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is invalid per the Fetch spec and browsers should reject it, but it signals a misconfigured CORS policy.", rationale: "Indicates the CORS configuration was not deliberately restricted.", evidence: `Access-Control-Allow-Origin: ${allowOrigin}; Access-Control-Allow-Credentials: ${allowCredentials}` });
    } else if (cors.reflectsOrigin) {
      findings.push({ rule: "web.cors-reflects-origin", severity: "LOW", category: "web", title: "CORS reflects an arbitrary Origin", description: `Access-Control-Allow-Origin echoed back an origin the site has never seen before (${probeOrigin}).`, rationale: "Equivalent to Access-Control-Allow-Origin: * for any caller that does not send credentials, but worth confirming it's intentional.", evidence: `Access-Control-Allow-Origin: ${allowOrigin}` });
    }
  } catch {
    // CORS probing is best-effort; its absence is not itself reported.
  }

  const title = extractTitle(res.body);
  const technologies = detectTechnologies(headers, res.body);
  if (robotsRes.present && robotsRes.excerpt) {
    const sensitive = [...robotsRes.excerpt.matchAll(/^disallow:\s*(\S+)/gim)].map((m) => m[1]).filter((p) => /admin|wp-admin|\.git|\.env|backup|config|internal|private/i.test(p));
    if (sensitive.length) findings.push({ rule: "web.robots-sensitive-paths", severity: "INFO", category: "web", title: "robots.txt names sensitive-looking paths", description: "Disallow entries point at paths worth checking for exposure, since robots.txt is public and only asks well-behaved crawlers not to index them.", rationale: "robots.txt does not restrict access — it is a hint to crawlers, not a security control.", evidence: sensitive.slice(0, 8).join(", ") });
  }

  return {
    url: base.toString(),
    finalUrl: res.url,
    status: res.status,
    https: finalUrl.protocol === "https:",
    hops: res.hops,
    title,
    server: headers.server,
    poweredBy: headers["x-powered-by"],
    tls: res.tls,
    headers,
    setCookies: res.setCookies.map(parseSetCookie),
    checks: analysis.checks,
    robots: robotsRes,
    securityTxt,
    sitemap: { ...sitemapRes, urlCount: sitemapUrlCount },
    cors,
    technologies,
    findings: findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)),
    bodyTruncated: res.bodyTruncated,
    durationMs: Date.now() - started,
  };
}

export { TargetRequestError };
