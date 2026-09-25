import type { NormalizedFinding } from "@/lib/core/types";
import { hostnameInfo } from "./detect";
import { classifyIp, isIpv4, normalizeIpv6 } from "./ip";

export interface UrlAnalysis {
  url: string;
  protocol: string;
  hostname: string;
  hostType: "domain" | "ipv4" | "ipv6";
  port: number;
  defaultPort: boolean;
  pathname: string;
  query: { key: string; value: string }[];
  fragment: string | null;
  username: string | null;
  hasPassword: boolean;
  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  privateSuffix: string | null;
  unicodeHostname: string | null;
  fileExtension: string | null;
  length: number;
  findings: NormalizedFinding[];
}

const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "scr", "dll", "msi", "bat", "cmd", "com", "pif", "cpl", "hta", "js", "jse", "vbs", "vbe", "wsf", "ps1",
  "psm1", "jar", "apk", "elf", "sh", "lnk", "iso", "img", "vhd", "vhdx", "xll", "one", "msix", "appx",
]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "gz", "tgz", "cab", "ace", "arj", "xz", "bz2"]);
const REDIRECT_PARAMS = new Set(["url", "u", "redirect", "redirect_uri", "redirect_url", "next", "return", "returnurl", "return_to", "dest", "destination", "target", "continue", "goto", "out", "link"]);

/** Unicode scripts present in a string (rough, for homograph detection). */
function scriptsOf(text: string): Set<string> {
  const scripts = new Set<string>();
  for (const ch of text) {
    if (/[a-z]/i.test(ch)) scripts.add("Latin");
    else if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add("Cyrillic");
    else if (/\p{Script=Greek}/u.test(ch)) scripts.add("Greek");
    else if (/\p{Script=Armenian}/u.test(ch)) scripts.add("Armenian");
    else if (/\p{Script=Latin}/u.test(ch)) scripts.add("Latin");
  }
  return scripts;
}

export function analyzeUrl(raw: string): UrlAnalysis | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;

  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const hostType: UrlAnalysis["hostType"] = isIpv4(hostname) ? "ipv4" : normalizeIpv6(hostname) ? "ipv6" : "domain";
  const defaultPortNumber = url.protocol === "https:" ? 443 : 80;
  const port = url.port ? Number(url.port) : defaultPortNumber;
  const info = hostType === "domain" ? hostnameInfo(hostname) : null;
  const lastSegment = url.pathname.split("/").filter(Boolean).pop() ?? "";
  const extMatch = lastSegment.match(/\.([a-z0-9]{1,8})$/i);
  const fileExtension = extMatch ? extMatch[1].toLowerCase() : null;
  const query = [...url.searchParams.entries()].map(([key, value]) => ({ key, value }));
  const findings: NormalizedFinding[] = [];

  if (url.username || url.password) {
    findings.push({
      rule: "url.userinfo",
      severity: "MEDIUM",
      category: "url",
      title: "URL contains embedded credentials or userinfo",
      description: `The URL carries a userinfo component ("${url.username}${url.password ? ":••••" : ""}@") before the real host.`,
      rationale:
        "Userinfo is rarely legitimate in web links and is a classic obfuscation technique: text before the @ can imitate a trusted brand while the browser connects to the host after it.",
      evidence: `Parsed host is ${hostname}; userinfo "${url.username}" precedes it.`,
      evidenceData: { host: hostname, username: url.username, passwordPresent: Boolean(url.password) },
    });
  }

  if (hostType !== "domain") {
    const scope = classifyIp(hostname)?.scope ?? "unknown";
    findings.push({
      rule: "url.ip-host",
      severity: "LOW",
      category: "url",
      title: "URL uses a raw IP address instead of a hostname",
      description: `The host component is the literal ${hostType === "ipv4" ? "IPv4" : "IPv6"} address ${hostname} (${scope}).`,
      rationale:
        "Legitimate services almost always publish hostnames. Direct-to-IP URLs are common for malware delivery and command-and-control because they avoid DNS-based controls and domain reputation.",
      evidence: `Host: ${hostname}`,
      evidenceData: { host: hostname, scope },
    });
  }

  if (info?.isIdn && info.unicode) {
    const scripts = scriptsOf(info.unicode.replace(/\./g, ""));
    const mixed = scripts.size > 1;
    findings.push({
      rule: mixed ? "host.idn-mixed-script" : "host.idn",
      severity: mixed ? "MEDIUM" : "INFO",
      category: "host",
      title: mixed ? "Internationalised hostname mixes writing systems" : "Internationalised (punycode) hostname",
      description: `${hostname} decodes to "${info.unicode}"${mixed ? `, mixing ${[...scripts].join(" and ")} characters` : ""}.`,
      rationale: mixed
        ? "Mixing scripts in one label is a hallmark of homograph attacks, where look-alike characters imitate a familiar domain."
        : "Punycode hostnames are legitimate for many languages but deserve a visual check against look-alike brands.",
      evidence: `ASCII: ${hostname} · Unicode: ${info.unicode}`,
      evidenceData: { ascii: hostname, unicode: info.unicode, scripts: [...scripts] },
    });
  }

  if (url.port && port !== defaultPortNumber) {
    findings.push({
      rule: "url.nonstandard-port",
      severity: "INFO",
      category: "url",
      title: `Non-standard port ${port}`,
      description: `The URL targets port ${port} rather than the ${url.protocol.replace(":", "").toUpperCase()} default ${defaultPortNumber}.`,
      rationale: "Services on unusual ports are more often development, administrative or ad-hoc infrastructure.",
      evidence: `Port: ${port}`,
    });
  }

  if (fileExtension && (EXECUTABLE_EXTENSIONS.has(fileExtension) || ARCHIVE_EXTENSIONS.has(fileExtension))) {
    const executable = EXECUTABLE_EXTENSIONS.has(fileExtension);
    findings.push({
      rule: executable ? "url.executable-path" : "url.archive-path",
      severity: executable ? "MEDIUM" : "LOW",
      category: "url",
      title: executable ? `URL path points to executable content (.${fileExtension})` : `URL path points to an archive (.${fileExtension})`,
      description: `The final path segment "${lastSegment}" has a .${fileExtension} extension.`,
      rationale: executable
        ? "Direct links to executables and script files are a primary malware delivery mechanism."
        : "Archives are frequently used to smuggle executables past mail and web filters.",
      evidence: `Path: ${url.pathname}`,
    });
  }

  const embedded = query.filter((q) => REDIRECT_PARAMS.has(q.key.toLowerCase()) && /^(https?:)?\/\//i.test(q.value));
  if (embedded.length) {
    findings.push({
      rule: "url.embedded-redirect",
      severity: "LOW",
      category: "url",
      title: "Query parameter carries another URL",
      description: `Parameter "${embedded[0].key}" contains ${embedded[0].value.slice(0, 120)}.`,
      rationale:
        "Redirect parameters on trusted domains are abused as open redirectors to launder malicious destinations behind a reputable hostname.",
      evidence: embedded.map((q) => `${q.key}=${q.value.slice(0, 80)}`).join(", "),
    });
  }

  if (info?.subdomain && info.subdomain.split(".").length >= 4) {
    findings.push({
      rule: "host.deep-subdomain",
      severity: "INFO",
      category: "host",
      title: "Deeply nested subdomain",
      description: `The hostname has ${info.subdomain.split(".").length} subdomain levels below ${info.registrableDomain}.`,
      rationale: "Long subdomain chains are used to place a trusted brand name at the start of a hostname controlled by someone else.",
      evidence: `Subdomain: ${info.subdomain}`,
    });
  }

  if (info?.privateSuffix) {
    findings.push({
      rule: "host.private-suffix",
      severity: "INFO",
      category: "host",
      title: `Hosted under a shared platform suffix (${info.privateSuffix})`,
      description: `${info.privateSuffix} is listed in the private section of the Public Suffix List, meaning subdomains are handed out to unrelated users.`,
      rationale:
        "Reputation of the parent platform says nothing about an individual tenant; dynamic DNS and free hosting suffixes are commonly abused.",
      evidence: `Public Suffix List private entry: ${info.privateSuffix}`,
    });
  }

  if (url.href.length > 250) {
    findings.push({
      rule: "url.long",
      severity: "INFO",
      category: "url",
      title: "Unusually long URL",
      description: `The URL is ${url.href.length} characters long.`,
      rationale: "Very long URLs can hide the true destination in link previews and are common in tracking and phishing kits.",
      evidence: `Length: ${url.href.length}`,
    });
  }

  if (url.protocol === "http:") {
    findings.push({
      rule: "url.cleartext",
      severity: "INFO",
      category: "url",
      title: "URL uses unencrypted HTTP",
      description: "The URL specifies http://, so content and any submitted data travel unencrypted unless the server redirects to HTTPS.",
      evidence: `Scheme: ${url.protocol}`,
    });
  }

  return {
    url: url.toString(),
    protocol: url.protocol.replace(":", ""),
    hostname,
    hostType,
    port,
    defaultPort: port === defaultPortNumber,
    pathname: url.pathname,
    query,
    fragment: url.hash ? url.hash.slice(1) : null,
    username: url.username || null,
    hasPassword: Boolean(url.password),
    registrableDomain: info?.registrableDomain ?? null,
    publicSuffix: info?.publicSuffix ?? null,
    subdomain: info?.subdomain ?? null,
    privateSuffix: info?.privateSuffix ?? null,
    unicodeHostname: info?.unicode ?? null,
    fileExtension,
    length: url.href.length,
    findings,
  };
}
