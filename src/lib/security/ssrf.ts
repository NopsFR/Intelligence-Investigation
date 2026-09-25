import dns from "node:dns/promises";
import net from "node:net";

/**
 * Blocks requests to loopback, private, link-local, multicast, and cloud
 * metadata address ranges. Used to validate both the initial destination of
 * a user-supplied URL and every redirect hop it produces.
 */
function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return true;
  const [a, b] = parts;

  if (a === 127) return true; // loopback
  if (a === 10) return true; // private
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
  if (a === 0) return true; // "this" network
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast/reserved
  return false;
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::1") return true; // loopback
  if (lower.startsWith("::ffff:")) {
    // IPv4-mapped — validate the embedded IPv4 address.
    const mapped = lower.split(":").pop() ?? "";
    if (net.isIPv4(mapped)) return isBlockedIpv4(mapped);
  }
  if (lower.startsWith("fe80:")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local
  if (lower.startsWith("ff")) return true; // multicast
  if (lower === "::") return true;
  return false;
}

export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) return isBlockedIpv4(ip);
  if (net.isIPv6(ip)) return isBlockedIpv6(ip);
  return true; // unrecognized format — deny by default
}

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.internal",
]);

export class SsrfBlockedError extends Error {
  constructor(host: string) {
    super(`Destination "${host}" is blocked by SSRF protection`);
    this.name = "SsrfBlockedError";
  }
}

/**
 * Resolves a hostname and verifies every resolved address is safe to
 * connect to. Throws SsrfBlockedError if the destination (or any resolved
 * address) is disallowed. Must be called for the initial URL and again
 * after every redirect hop, since DNS can be re-pointed between requests.
 */
export async function assertSafeDestination(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfBlockedError(rawUrl);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfBlockedError(url.href);
  }

  const hostname = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new SsrfBlockedError(hostname);
  }

  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) throw new SsrfBlockedError(hostname);
    return url;
  }

  let addresses: string[];
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    addresses = records.map((r) => r.address);
  } catch {
    throw new SsrfBlockedError(hostname);
  }

  if (addresses.length === 0) throw new SsrfBlockedError(hostname);
  for (const addr of addresses) {
    if (isBlockedIp(addr)) throw new SsrfBlockedError(`${hostname} (${addr})`);
  }

  return url;
}
