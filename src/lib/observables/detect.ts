import { parse as parseDomain } from "tldts";
import type { ObservableType } from "@/lib/core/types";
import { refang } from "./fang";
import { isIpv4, normalizeIpv6 } from "./ip";

export interface DetectedObservable {
  raw: string;
  normalized: string;
  type: ObservableType;
  /** Other plausible interpretations of the same input. */
  alternatives: ObservableType[];
  /** Transformations applied while normalising (refanging, port removal, ...). */
  notes: string[];
}

const MD5_RE = /^[a-f0-9]{32}$/i;
const SHA1_RE = /^[a-f0-9]{40}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const CERT_FP_RE = /^([a-f0-9]{2}:){31}[a-f0-9]{2}$/i;
const CVE_RE = /^CVE-(\d{4})-(\d{4,})$/i;
const ASN_RE = /^AS[N]?\s*(\d{1,10})$/i;
const EMAIL_RE = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@([^\s@]+)$/i;
const HOST_LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** Validates and normalises a hostname to lowercase ASCII (punycode for IDNs). */
export function normalizeHostname(input: string): string | null {
  const host = input.trim().replace(/\.$/, "");
  if (!host || host.length > 253 || /\s/.test(host)) return null;
  let ascii: string;
  try {
    ascii = new URL(`http://${host}/`).hostname;
  } catch {
    return null;
  }
  if (ascii !== host.toLowerCase() && !/[^\x00-\x7f]/.test(host)) return null;
  const labels = ascii.split(".");
  if (labels.length < 2) return null;
  if (!labels.every((l) => HOST_LABEL_RE.test(l))) return null;
  const info = parseDomain(ascii, { allowPrivateDomains: true });
  if (!info.publicSuffix || !(info.isIcann || info.isPrivate)) return null;
  if (!info.domain) return null;
  return ascii;
}

export function detectObservable(input: string): DetectedObservable | null {
  const raw = input;
  let value = input.trim();
  if (!value || value.length > 2048) return null;
  const notes: string[] = [];

  const refanged = refang(value);
  if (refanged !== value) {
    notes.push("Refanged defanged indicator");
    value = refanged;
  }

  const make = (type: ObservableType, normalized: string, alternatives: ObservableType[] = []): DetectedObservable => ({
    raw,
    normalized,
    type,
    alternatives,
    notes,
  });

  // URL with an explicit web scheme.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return null;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (!url.hostname) return null;
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (!isIpv4(host) && !normalizeIpv6(host) && !normalizeHostname(host)) return null;
    return make("URL", url.toString());
  }

  const cve = value.match(CVE_RE);
  if (cve) return make("CVE", `CVE-${cve[1]}-${cve[2]}`);

  const asn = value.match(ASN_RE);
  if (asn) {
    const n = Number(asn[1]);
    if (n > 0 && n <= 4294967295) return make("ASN", `AS${n}`);
    return null;
  }

  if (CERT_FP_RE.test(value)) return make("CERT_SHA256", value.replace(/:/g, "").toLowerCase(), ["SHA256"]);
  if (SHA256_RE.test(value)) return make("SHA256", value.toLowerCase(), ["CERT_SHA256"]);
  if (SHA1_RE.test(value)) return make("SHA1", value.toLowerCase());
  if (MD5_RE.test(value)) return make("MD5", value.toLowerCase());

  // IPv4, optionally with a port.
  const v4port = value.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
  if (v4port && isIpv4(v4port[1])) {
    notes.push(`Removed port :${v4port[2]}`);
    return make("IPV4", v4port[1]);
  }
  if (isIpv4(value)) return make("IPV4", value);

  const v6 = normalizeIpv6(value.replace(/^\[(.*)\](:\d+)?$/, "$1"));
  if (v6) return make("IPV6", v6);

  const email = value.match(EMAIL_RE);
  if (email) {
    const host = normalizeHostname(email[1]);
    if (!host) return null;
    const local = value.slice(0, value.lastIndexOf("@"));
    if (local.length > 64) return null;
    return make("EMAIL", `${local}@${host}`, ["DOMAIN"]);
  }

  // Scheme-less URL such as example[.]com/login.php
  const slash = value.indexOf("/");
  if (slash > 0) {
    const hostPart = value.slice(0, slash).replace(/:\d+$/, "");
    if (normalizeHostname(hostPart) || isIpv4(hostPart)) {
      try {
        const url = new URL(`http://${value}`);
        notes.push("Assumed http:// scheme for scheme-less URL");
        return make("URL", url.toString());
      } catch {
        return null;
      }
    }
  }

  const host = normalizeHostname(value);
  if (host) return make("DOMAIN", host);

  return null;
}

/** Detects the observable, then forces a specific interpretation if allowed. */
export function detectAs(input: string, type?: ObservableType): DetectedObservable | null {
  const detected = detectObservable(input);
  if (!detected || !type || type === detected.type) return detected;
  if (!detected.alternatives.includes(type)) return null;
  if (type === "DOMAIN" && detected.type === "EMAIL") {
    return { ...detected, type, normalized: detected.normalized.split("@")[1], alternatives: [], notes: [...detected.notes, "Investigating the email domain"] };
  }
  if (type === "CERT_SHA256" || type === "SHA256") {
    return { ...detected, type, alternatives: [detected.type] };
  }
  return null;
}

export function isHashType(type: ObservableType): boolean {
  return type === "MD5" || type === "SHA1" || type === "SHA256";
}

/** Registrable domain (eTLD+1) for a hostname, using the Public Suffix List. */
export function registrableDomain(hostname: string): string | null {
  const info = parseDomain(hostname, { allowPrivateDomains: false });
  return info.domain ?? null;
}

export interface HostnameInfo {
  hostname: string;
  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  /** Suffix is on the private section of the PSL (dynamic DNS, hosting platforms). */
  privateSuffix: string | null;
  isIdn: boolean;
  unicode: string | null;
}

export function hostnameInfo(hostname: string): HostnameInfo {
  const icann = parseDomain(hostname, { allowPrivateDomains: false });
  const withPrivate = parseDomain(hostname, { allowPrivateDomains: true });
  const isIdn = hostname.split(".").some((l) => l.startsWith("xn--"));
  let unicode: string | null = null;
  if (isIdn) {
    try {
      unicode = decodePunycodeHost(hostname);
    } catch {
      unicode = null;
    }
  }
  return {
    hostname,
    registrableDomain: icann.domain ?? null,
    publicSuffix: icann.publicSuffix ?? null,
    subdomain: icann.subdomain || null,
    privateSuffix: withPrivate.isPrivate ? withPrivate.publicSuffix ?? null : null,
    isIdn,
    unicode,
  };
}

// Minimal RFC 3492 punycode decoder (browser-safe; node:punycode is deprecated).
function decodePunycodeLabel(input: string): string {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  let n = 128;
  let i = 0;
  let bias = 72;
  const output: number[] = [];
  const basic = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(basic, 0); j++) output.push(input.charCodeAt(j));
  const adapt = (delta: number, numPoints: number, firstTime: boolean) => {
    let k = 0;
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
    return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
  };
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= input.length) throw new Error("invalid punycode");
      const cp = input.charCodeAt(idx++);
      const digit = cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : base;
      if (digit >= base) throw new Error("invalid punycode");
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

export function decodePunycodeHost(hostname: string): string {
  return hostname
    .split(".")
    .map((label) => (label.startsWith("xn--") ? decodePunycodeLabel(label.slice(4)) : label))
    .join(".");
}
