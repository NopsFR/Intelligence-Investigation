import type { DetectedObservable, ObservableType } from "@/types/observable";

const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;

// Intentionally permissive; validity of each hextet is checked separately.
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;

const DOMAIN_RE =
  /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

const MD5_RE = /^[a-fA-F0-9]{32}$/;
const SHA1_RE = /^[a-fA-F0-9]{40}$/;
const SHA256_RE = /^[a-fA-F0-9]{64}$/;

const CVE_RE = /^CVE-\d{4}-\d{4,19}$/i;
const ASN_RE = /^(AS|ASN)?\s?(\d{1,10})$/i;

function isValidIpv6(value: string): boolean {
  if (!IPV6_RE.test(value)) return false;
  const doubleColonCount = (value.match(/::/g) ?? []).length;
  if (doubleColonCount > 1) return false;
  const groups = value.split(":");
  if (doubleColonCount === 0 && groups.length !== 8) return false;
  if (groups.length > 8) return false;
  return true;
}

/**
 * Detects the observable type of a raw string input. Returns null when the
 * input does not match any supported observable format.
 */
export function detectObservable(input: string): DetectedObservable | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  // URL — must have a scheme to be unambiguous vs. a bare domain.
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      const url = new URL(trimmed);
      if (url.protocol === "http:" || url.protocol === "https:") {
        return { raw: input, normalized: url.toString(), type: "URL" };
      }
    } catch {
      return null;
    }
  }

  if (CVE_RE.test(trimmed)) {
    return { raw: input, normalized: trimmed.toUpperCase(), type: "CVE" };
  }

  if (ASN_RE.test(trimmed)) {
    const match = trimmed.match(ASN_RE);
    const num = match?.[2];
    if (num) {
      return { raw: input, normalized: `AS${num}`, type: "ASN" };
    }
  }

  if (SHA256_RE.test(trimmed)) {
    return { raw: input, normalized: trimmed.toLowerCase(), type: "SHA256" };
  }
  if (SHA1_RE.test(trimmed)) {
    return { raw: input, normalized: trimmed.toLowerCase(), type: "SHA1" };
  }
  if (MD5_RE.test(trimmed)) {
    return { raw: input, normalized: trimmed.toLowerCase(), type: "MD5" };
  }

  if (IPV4_RE.test(trimmed)) {
    return { raw: input, normalized: trimmed, type: "IPV4" };
  }

  if (trimmed.includes(":") && isValidIpv6(trimmed)) {
    return { raw: input, normalized: trimmed.toLowerCase(), type: "IPV6" };
  }

  if (DOMAIN_RE.test(trimmed) && !/^\d+(\.\d+){3}$/.test(trimmed)) {
    return { raw: input, normalized: trimmed.toLowerCase(), type: "DOMAIN" };
  }

  return null;
}

export function typeIsHash(type: ObservableType): boolean {
  return type === "MD5" || type === "SHA1" || type === "SHA256";
}
