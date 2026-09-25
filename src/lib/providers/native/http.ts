import "server-only";
import type { NormalizedFinding, NormalizedRelationship } from "@/lib/core/types";
import { TargetRequestError, targetRequest, type TargetHop, type TargetResponse } from "@/lib/net/target";
import { registrableDomain } from "@/lib/observables/detect";
import { analyzeSecurityHeaders, extractTitle, type HeaderCheck } from "@/lib/web/headers";
import { fact, facts } from "../helpers";
import type { ProviderDefinition } from "../types";

const DOWNLOAD_TYPES = /^(application\/(octet-stream|x-msdownload|x-msdos-program|x-dosexec|vnd\.microsoft\.portable-executable|x-executable|java-archive|vnd\.android\.package-archive|x-msi|zip|x-zip-compressed|x-rar-compressed|vnd\.rar|x-7z-compressed|gzip|x-iso9660-image|hta)|application\/x-sh)/i;
const SELECTED_HEADERS = [
  "server",
  "content-type",
  "content-length",
  "content-disposition",
  "location",
  "strict-transport-security",
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "x-powered-by",
  "via",
  "cf-ray",
  "x-cache",
  "age",
  "cache-control",
];

interface PageSignals {
  title?: string;
  metaRefresh?: string;
  passwordField: boolean;
  externalFormActions: string[];
}

function header(res: TargetResponse, name: string): string | undefined {
  const v = res.headers[name];
  return Array.isArray(v) ? v.join(", ") : v;
}

function pageSignals(res: TargetResponse): PageSignals {
  const contentType = header(res, "content-type") ?? "";
  if (!/html/i.test(contentType)) return { passwordField: false, externalFormActions: [] };
  const html = res.body;
  const refresh = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']([^"']+)["']/i)?.[1];
  const host = new URL(res.url).hostname;
  const actions: string[] = [];
  for (const m of html.matchAll(/<form[^>]+action\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const target = new URL(m[1], res.url);
      if ((target.protocol === "http:" || target.protocol === "https:") && registrableDomain(target.hostname) !== registrableDomain(host)) actions.push(target.origin);
    } catch {
      // Unparseable action: ignore.
    }
  }
  return {
    title: extractTitle(html),
    metaRefresh: refresh?.match(/url\s*=\s*['"]?([^'";]+)/i)?.[1]?.trim(),
    passwordField: /<input[^>]+type\s*=\s*["']?password/i.test(html),
    externalFormActions: [...new Set(actions)].slice(0, 5),
  };
}

function selectedHeaders(res: TargetResponse): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of SELECTED_HEADERS) {
    const v = header(res, name);
    if (v) out[name] = v.length > 600 ? `${v.slice(0, 600)}…` : v;
  }
  return out;
}

function chainText(hops: TargetHop[]): string {
  return hops.map((h) => `${h.status} ${h.url}`).join(" → ");
}

function hostOf(url: string): string {
  return new URL(url).hostname.replace(/^\[|\]$/g, "");
}

/** Findings about the redirect chain and the delivered content (URL investigations). */
function deliveryFindings(requested: string, res: TargetResponse, page: PageSignals): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const startHost = hostOf(requested);
  const finalHost = hostOf(res.url);

  const downgrade = res.hops.findIndex((h, i) => i > 0 && h.url.startsWith("http:") && res.hops[i - 1].url.startsWith("https:"));
  if (downgrade > 0) {
    findings.push({
      rule: "http.redirect-downgrade",
      severity: "MEDIUM",
      category: "web",
      title: "Redirect chain downgrades from HTTPS to HTTP",
      description: `The chain moves from ${res.hops[downgrade - 1].url} to cleartext ${res.hops[downgrade].url}.`,
      rationale: "Anything after the downgrade — including the final page — can be read or altered on the network path.",
      evidence: chainText(res.hops),
    });
  }

  if (registrableDomain(finalHost) !== registrableDomain(startHost)) {
    findings.push({
      rule: "http.redirect-cross-domain",
      severity: "INFO",
      category: "web",
      title: `Redirects to a different domain: ${finalHost}`,
      description: `Requesting ${startHost} ends at ${finalHost} after ${res.hops.length - 1} redirect(s).`,
      rationale: "Off-domain redirects are common for link shorteners and SSO, and are also how phishing and malware links hide their destination. Investigate the final domain on its own.",
      evidence: chainText(res.hops),
      observable: res.url,
    });
  }

  const contentType = header(res, "content-type") ?? "";
  const disposition = header(res, "content-disposition") ?? "";
  const attachment = /attachment/i.test(disposition);
  if (DOWNLOAD_TYPES.test(contentType) || attachment) {
    const filename = disposition.match(/filename\*?=(?:UTF-8'')?["']?([^"';]+)/i)?.[1];
    findings.push({
      rule: "http.serves-download",
      severity: "MEDIUM",
      category: "web",
      title: `URL delivers a file${filename ? `: ${filename}` : ""}`,
      description: `The response is a file download (${contentType || "no content type"}${attachment ? ", sent as an attachment" : ""}) rather than a web page.`,
      rationale: "Direct file delivery is how most malware-distribution URLs work. The file was not stored; check its hash against malware sources if you can obtain it safely.",
      evidence: `Content-Type: ${contentType || "—"}${disposition ? ` · Content-Disposition: ${disposition}` : ""}`,
      evidenceData: { contentType, ...(filename ? { filename } : {}), status: res.status },
    });
  }

  if (page.passwordField) {
    findings.push({
      rule: "http.credential-form",
      severity: "INFO",
      category: "web",
      title: "Page contains a password field",
      description: `The page served at ${res.url} asks for a password.`,
      rationale: "On its own this is normal for login pages. It becomes significant when combined with a young domain, a lookalike hostname or a form posting to another site.",
      evidence: `Password <input> present in HTML${page.title ? ` titled “${page.title}”` : ""}.`,
    });
  }

  if (page.externalFormActions.length) {
    findings.push({
      rule: "http.form-posts-offsite",
      severity: page.passwordField ? "MEDIUM" : "LOW",
      category: "web",
      title: `Form submits to another site: ${page.externalFormActions[0]}`,
      description: `A form on ${finalHost} posts its data to ${page.externalFormActions.join(", ")}.`,
      rationale: page.passwordField
        ? "A password form that submits to a different domain is a classic credential-harvesting pattern."
        : "Data entered on this page is sent to a third party.",
      evidence: `form action → ${page.externalFormActions.join(", ")}`,
    });
  }

  if (page.metaRefresh) {
    findings.push({
      rule: "http.client-redirect",
      severity: "INFO",
      category: "web",
      title: "Page redirects in the browser",
      description: `A meta refresh sends visitors on to ${page.metaRefresh}.`,
      rationale: "Client-side redirects are not visible in the HTTP redirect chain and are often used to evade URL scanners.",
      evidence: `<meta http-equiv="refresh"> → ${page.metaRefresh}`,
    });
  }
  return findings;
}

async function upgradeCheck(host: string) {
  try {
    const res = await targetRequest(`http://${host}/`, { maxRedirects: 0, timeoutMs: 6000, maxBodyBytes: 16 * 1024 });
    const location = header(res, "location");
    let upgrades = false;
    if (location && [301, 302, 303, 307, 308].includes(res.status)) {
      try {
        const next = new URL(location, `http://${host}/`);
        upgrades = next.protocol === "https:";
      } catch {
        upgrades = false;
      }
    }
    return { reachable: true as const, status: res.status, location, upgrades, permanent: res.status === 301 || res.status === 308 };
  } catch (err) {
    return { reachable: false as const, error: err instanceof TargetRequestError ? err.message : "request failed" };
  }
}

export const httpInspection: ProviderDefinition = {
  id: "http",
  code: "WEB",
  name: "HTTP response & headers",
  vendor: "Native · direct HTTP request",
  category: "web",
  kind: "native",
  active: true,
  description:
    "Requests the site or URL directly: redirect chain, final destination, content type, page title, HTTP→HTTPS upgrade and a security-header review (HSTS, CSP, framing, CORS, cookies).",
  homepage: "https://owasp.org/www-project-secure-headers/",
  auth: { type: "none" },
  endpoint: "HTTP(S) · ports 80/443/8080/8443 · SSRF-guarded, every redirect re-validated",
  supports: ["DOMAIN", "URL"],
  quick: "none",
  cacheTtlSeconds: 15 * 60,
  timeoutMs: 25_000,
  healthCheck: { observable: "example.com", type: "DOMAIN" },
  async run(ctx) {
    const isDomain = ctx.type === "DOMAIN";
    const requested = isDomain ? `https://${ctx.observable}/` : ctx.observable;

    const [primary, upgrade] = await Promise.all([
      targetRequest(requested, { maxRedirects: 8, timeoutMs: 9000 }).catch((err: unknown) => err as Error),
      isDomain ? upgradeCheck(ctx.observable) : Promise.resolve(null),
    ]);

    const findings: NormalizedFinding[] = [];
    const relationships: NormalizedRelationship[] = [];

    if (primary instanceof Error) {
      // HTTPS failed. For a domain, a working cleartext site is still worth reporting.
      if (isDomain && upgrade?.reachable) {
        findings.push({
          rule: "http.no-https",
          severity: "MEDIUM",
          category: "web",
          title: "Site is only reachable over plain HTTP",
          description: `https://${ctx.observable}/ could not be retrieved (${primary.message}), but http://${ctx.observable}/ answered with HTTP ${upgrade.status}.`,
          rationale: "Without HTTPS, everything exchanged with the site can be read and modified in transit.",
          evidence: `HTTPS: ${primary.message} · HTTP: ${upgrade.status}${upgrade.location ? ` → ${upgrade.location}` : ""}`,
          remediation: "Serve the site over HTTPS with a valid certificate and redirect HTTP to HTTPS.",
        });
        return {
          summary: `HTTPS unavailable · HTTP ${upgrade.status}`,
          partial: true,
          listed: true,
          facts: facts(
            fact("https", "HTTPS", `Failed: ${primary.message}`, "text", true),
            fact("httpStatus", "HTTP (port 80) status", upgrade.status, "number", true),
            fact("httpLocation", "HTTP redirects to", upgrade.location, "url")
          ),
          data: { kind: "http", requested, error: primary.message, upgrade, checks: [] as HeaderCheck[] },
          findings,
        };
      }
      throw primary;
    }

    const res = primary;
    const page = pageSignals(res);
    const finalHost = hostOf(res.url);
    const https = res.url.startsWith("https:");
    const headerAnalysis = analyzeSecurityHeaders(res.headers, { https, host: finalHost, setCookies: res.setCookies });

    if (isDomain) {
      // Header findings describe the investigated site; skip them when it hands off elsewhere.
      if (registrableDomain(finalHost) === registrableDomain(ctx.observable)) findings.push(...headerAnalysis.findings);
      if (upgrade?.reachable && !upgrade.upgrades) {
        findings.push({
          rule: "http.no-https-redirect",
          severity: "LOW",
          category: "web",
          title: "HTTP is not redirected to HTTPS",
          description: `http://${ctx.observable}/ answers with HTTP ${upgrade.status}${upgrade.location ? ` and redirects to ${upgrade.location}` : ""} instead of upgrading to HTTPS.`,
          rationale: "Visitors who type the bare domain or follow an old link stay on an unencrypted connection.",
          evidence: `GET http://${ctx.observable}/ → ${upgrade.status}${upgrade.location ? ` Location: ${upgrade.location}` : ""}`,
          remediation: "Return a 301 or 308 redirect from HTTP to the HTTPS URL.",
        });
      }
    }
    findings.push(...deliveryFindings(requested, res, page).filter((f) => !isDomain || f.rule !== "http.credential-form"));

    if (res.url !== requested) {
      relationships.push({
        source: isDomain ? { type: "domain", value: ctx.observable } : { type: "url", value: requested },
        target: { type: "url", value: res.url },
        type: "redirects-to",
        evidence: chainText(res.hops),
      });
    }
    if (!isDomain) {
      relationships.push({
        source: { type: "url", value: res.url },
        target: { type: "domain", value: finalHost },
        type: "hosted-on",
        evidence: "Final URL hostname.",
      });
    }

    const contentType = header(res, "content-type");
    const server = header(res, "server");
    return {
      summary: `HTTP ${res.status}${res.hops.length > 1 ? ` after ${res.hops.length - 1} redirect(s)` : ""}${page.title ? ` · “${page.title}”` : ""}`,
      listed: true,
      facts: facts(
        fact("status", "Final status", res.status, "number", true),
        fact("finalUrl", "Final URL", res.url, "url", true),
        fact("redirects", "Redirects", res.hops.length - 1, "number"),
        fact("title", "Page title", page.title, "text", true),
        fact("contentType", "Content type", contentType, "mono"),
        fact("server", "Server", server, "mono"),
        fact("tls", "TLS", res.tls?.protocol ?? undefined, "mono"),
        fact("upgrade", "HTTP → HTTPS redirect", upgrade?.reachable ? upgrade.upgrades : undefined, "bool"),
        fact("cookies", "Cookies set", res.setCookies.length || undefined, "number"),
        fact("passwordField", "Password field on page", page.passwordField || undefined, "bool")
      ),
      data: {
        kind: "http",
        requested,
        finalUrl: res.url,
        status: res.status,
        hops: res.hops,
        headers: selectedHeaders(res),
        checks: headerAnalysis.checks,
        headerFindingsApplied: isDomain,
        title: page.title,
        contentType,
        bodyBytes: Buffer.byteLength(res.body),
        bodyTruncated: res.bodyTruncated,
        tls: res.tls,
        upgrade,
        page,
      },
      findings,
      relationships,
      raw: { hops: res.hops, headers: selectedHeaders(res), upgrade },
    };
  },
};
