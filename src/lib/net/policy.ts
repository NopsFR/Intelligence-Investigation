import "server-only";
import dns from "node:dns";
import type { LookupAddress, LookupOptions } from "node:dns";
import { classifyIp, isIpv4, normalizeIpv6 } from "@/lib/observables/ip";

export class NetworkPolicyError extends Error {
  constructor(message: string, public readonly reason: string) {
    super(message);
    this.name = "NetworkPolicyError";
  }
}

/** Ports the server will connect to for user-supplied destinations. */
export const ALLOWED_TARGET_PORTS = new Set([80, 443, 8080, 8443]);

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata",
  "instance-data",
  "kubernetes.default",
]);

const BLOCKED_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".intranet",
  ".lan",
  ".home",
  ".corp",
  ".home.arpa",
  ".localdomain",
  ".svc",
  ".cluster.local",
  ".in-addr.arpa",
  ".ip6.arpa",
];

/** Rejects hostnames that can only refer to private or infrastructure resources. */
export function assertHostnameAllowed(hostname: string): void {
  const host = hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!host) throw new NetworkPolicyError("Empty hostname", "invalid-host");

  if (isIpv4(host) || normalizeIpv6(host)) {
    const c = classifyIp(host);
    if (!c || c.scope !== "public") {
      throw new NetworkPolicyError(`Address ${host} is ${c?.description ?? "not public"}`, "non-public-address");
    }
    return;
  }

  if (BLOCKED_HOSTNAMES.has(host) || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
    throw new NetworkPolicyError(`Hostname ${host} refers to an internal namespace`, "internal-hostname");
  }
  if (!host.includes(".")) {
    throw new NetworkPolicyError(`Single-label hostname ${host} is not allowed`, "internal-hostname");
  }
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/**
 * Drop-in replacement for dns.lookup used by outbound sockets. It resolves every
 * address for the name and fails the connection if ANY of them is non-public,
 * so validation happens on the exact resolution the socket connects to (no
 * check-then-use gap for DNS rebinding).
 */
export function safeLookup(hostname: string, options: LookupOptions | number | LookupCallback, callback?: LookupCallback): void {
  const cb = (typeof options === "function" ? options : callback) as LookupCallback;
  const opts: LookupOptions = typeof options === "object" && options !== null ? options : {};

  try {
    assertHostnameAllowed(hostname);
  } catch (err) {
    cb(Object.assign(err as Error, { code: "ENOTALLOWED" }) as NodeJS.ErrnoException, []);
    return;
  }

  dns.lookup(hostname, { all: true, verbatim: true, family: opts.family }, (err, addresses) => {
    if (err) return cb(err, []);
    const list = addresses as LookupAddress[];
    if (!list.length) return cb(Object.assign(new Error(`No addresses for ${hostname}`), { code: "ENOTFOUND" }), []);
    const blocked = list.find((a) => classifyIp(a.address)?.scope !== "public");
    if (blocked) {
      const scope = classifyIp(blocked.address)?.description ?? "non-public";
      const e = new NetworkPolicyError(`${hostname} resolves to ${blocked.address} (${scope})`, "non-public-address");
      return cb(Object.assign(e, { code: "ENOTALLOWED" }) as unknown as NodeJS.ErrnoException, []);
    }
    if (opts.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}

/** Resolves and validates a hostname ahead of a raw socket connection (TLS inspection). */
export function resolvePublicAddress(hostname: string): Promise<LookupAddress> {
  return new Promise((resolve, reject) => {
    safeLookup(hostname, {}, (err, address, family) => {
      if (err) reject(err);
      else resolve({ address: address as string, family: family ?? 4 });
    });
  });
}
