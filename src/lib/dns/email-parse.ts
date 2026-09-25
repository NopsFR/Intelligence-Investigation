// Pure parsers for email-authentication DNS records (SPF, DMARC, DKIM, MTA-STS,
// TLS-RPT, BIMI). No network access — see providers/native/email.ts.

export type SpfQualifier = "+" | "-" | "~" | "?";

export interface SpfTerm {
  qualifier: SpfQualifier;
  mechanism: string;
  value?: string;
}

export interface ParsedSpf {
  valid: boolean;
  terms: SpfTerm[];
  all: SpfQualifier | null;
  redirect?: string;
  errors: string[];
}

const SPF_MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
/** Terms that cost a DNS lookup under RFC 7208 §4.6.4. */
export const SPF_LOOKUP_TERMS = new Set(["include", "a", "mx", "ptr", "exists", "redirect"]);

export function parseSpf(record: string): ParsedSpf {
  const errors: string[] = [];
  const parts = record.trim().split(/\s+/);
  if (parts[0]?.toLowerCase() !== "v=spf1") return { valid: false, terms: [], all: null, errors: ["Record does not start with v=spf1"] };
  const terms: SpfTerm[] = [];
  let all: SpfQualifier | null = null;
  let redirect: string | undefined;
  for (const raw of parts.slice(1)) {
    if (!raw) continue;
    const modifier = raw.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
    if (modifier) {
      if (modifier[1].toLowerCase() === "redirect") redirect = modifier[2];
      continue;
    }
    const qualifier = (["+", "-", "~", "?"].includes(raw[0]) ? raw[0] : "+") as SpfQualifier;
    const body = raw.replace(/^[+\-~?]/, "");
    const [mechanism, ...rest] = body.split(/[:/]/);
    const name = mechanism.toLowerCase();
    if (!SPF_MECHANISMS.has(name)) {
      errors.push(`Unknown mechanism "${raw}"`);
      continue;
    }
    const value = body.includes(":") ? body.slice(body.indexOf(":") + 1) : rest.length ? body.slice(mechanism.length) : undefined;
    terms.push({ qualifier, mechanism: name, value });
    if (name === "all") all = qualifier;
  }
  return { valid: errors.length === 0, terms, all, redirect, errors };
}

/** Parses semicolon-separated tag=value records (DMARC, DKIM, BIMI, TLS-RPT, MTA-STS TXT). */
export function parseTagList(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim().toLowerCase();
    const value = part.slice(idx + 1).trim();
    if (key && !(key in tags)) tags[key] = value;
  }
  return tags;
}

export interface ParsedDmarc {
  valid: boolean;
  policy?: string;
  subdomainPolicy?: string;
  pct: number;
  rua: string[];
  ruf: string[];
  adkim: "r" | "s";
  aspf: "r" | "s";
  tags: Record<string, string>;
  errors: string[];
}

export function parseDmarc(record: string): ParsedDmarc {
  const tags = parseTagList(record);
  const errors: string[] = [];
  if ((tags.v ?? "").toUpperCase() !== "DMARC1") errors.push("Missing v=DMARC1 as the first tag");
  const policy = tags.p?.toLowerCase();
  if (!policy) errors.push("Missing required p= tag");
  else if (!["none", "quarantine", "reject"].includes(policy)) errors.push(`Invalid policy "${tags.p}"`);
  const pct = tags.pct !== undefined ? Number(tags.pct) : 100;
  if (Number.isNaN(pct) || pct < 0 || pct > 100) errors.push(`Invalid pct "${tags.pct}"`);
  const list = (v?: string) => (v ? v.split(",").map((s) => s.trim()).filter(Boolean) : []);
  return {
    valid: errors.length === 0,
    policy,
    subdomainPolicy: tags.sp?.toLowerCase(),
    pct: Number.isNaN(pct) ? 100 : pct,
    rua: list(tags.rua),
    ruf: list(tags.ruf),
    adkim: tags.adkim?.toLowerCase() === "s" ? "s" : "r",
    aspf: tags.aspf?.toLowerCase() === "s" ? "s" : "r",
    tags,
    errors,
  };
}

export interface ParsedMtaStsPolicy {
  version?: string;
  mode?: string;
  mx: string[];
  maxAge?: number;
  errors: string[];
}

export function parseMtaStsPolicy(text: string): ParsedMtaStsPolicy {
  const mx: string[] = [];
  const out: ParsedMtaStsPolicy = { mx, errors: [] };
  for (const line of text.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === "version") out.version = value;
    else if (key === "mode") out.mode = value.toLowerCase();
    else if (key === "mx") mx.push(value.toLowerCase());
    else if (key === "max_age") out.maxAge = Number(value);
  }
  if (out.version !== "STSv1") out.errors.push("version must be STSv1");
  if (!out.mode || !["enforce", "testing", "none"].includes(out.mode)) out.errors.push("mode must be enforce, testing or none");
  if (out.mode !== "none" && !mx.length) out.errors.push("at least one mx pattern is required");
  if (out.maxAge === undefined || Number.isNaN(out.maxAge)) out.errors.push("max_age is required");
  return out;
}

/** Estimated RSA modulus size (bits) from a base64 SubjectPublicKeyInfo, used for DKIM key strength. */
export function estimateRsaBits(base64Key: string): number | null {
  const clean = base64Key.replace(/\s+/g, "");
  if (!clean) return null;
  const bytes = Math.floor((clean.length * 3) / 4) - (clean.endsWith("==") ? 2 : clean.endsWith("=") ? 1 : 0);
  // SPKI overhead for RSA keys is ~38 bytes (1024: 162B, 2048: 294B, 4096: 550B).
  if (bytes < 60) return null;
  const modulusBytes = bytes - 38;
  const candidates = [512, 768, 1024, 1536, 2048, 3072, 4096];
  return candidates.reduce((best, c) => (Math.abs(c / 8 - modulusBytes) < Math.abs(best / 8 - modulusBytes) ? c : best), 1024);
}

/** Common DKIM selectors used by major mail platforms (probing is best-effort). */
export const COMMON_DKIM_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "k2",
  "s1",
  "s2",
  "dkim",
  "mail",
  "smtp",
  "mandrill",
  "mxvault",
  "zoho",
  "protonmail",
  "sig1",
  "everlytickey1",
  "fm1",
  "cm",
];
