// IP address parsing and special-purpose range classification (IANA IPv4/IPv6
// Special-Purpose Address Registries, RFC 6890 and successors). Pure TypeScript
// so it runs in the browser, the server and the SSRF guard alike.

export type IpScope =
  | "public"
  | "private"
  | "loopback"
  | "link-local"
  | "shared"
  | "documentation"
  | "benchmarking"
  | "multicast"
  | "reserved"
  | "unspecified"
  | "broadcast"
  | "this-network"
  | "protocol-assignment"
  | "unique-local"
  | "discard"
  | "ipv4-mapped"
  | "translation";

export interface IpClassification {
  version: 4 | 6;
  address: string;
  scope: IpScope;
  range?: string;
  description: string;
  reference?: string;
  /** For IPv6 forms that embed an IPv4 address (mapped, NAT64, 6to4). */
  embeddedIpv4?: string;
}

interface RangeRule {
  cidr: string;
  scope: IpScope;
  description: string;
  reference: string;
}

const IPV4_RULES: RangeRule[] = [
  { cidr: "0.0.0.0/8", scope: "this-network", description: "\"This network\" source addresses", reference: "RFC 791" },
  { cidr: "10.0.0.0/8", scope: "private", description: "Private-use network", reference: "RFC 1918" },
  { cidr: "100.64.0.0/10", scope: "shared", description: "Shared address space (carrier-grade NAT)", reference: "RFC 6598" },
  { cidr: "127.0.0.0/8", scope: "loopback", description: "Loopback", reference: "RFC 1122" },
  { cidr: "169.254.0.0/16", scope: "link-local", description: "Link-local (includes cloud metadata 169.254.169.254)", reference: "RFC 3927" },
  { cidr: "172.16.0.0/12", scope: "private", description: "Private-use network", reference: "RFC 1918" },
  { cidr: "192.0.0.0/24", scope: "protocol-assignment", description: "IETF protocol assignments", reference: "RFC 6890" },
  { cidr: "192.0.2.0/24", scope: "documentation", description: "Documentation (TEST-NET-1)", reference: "RFC 5737" },
  { cidr: "192.88.99.0/24", scope: "reserved", description: "Deprecated 6to4 relay anycast", reference: "RFC 7526" },
  { cidr: "192.168.0.0/16", scope: "private", description: "Private-use network", reference: "RFC 1918" },
  { cidr: "198.18.0.0/15", scope: "benchmarking", description: "Network interconnect device benchmark testing", reference: "RFC 2544" },
  { cidr: "198.51.100.0/24", scope: "documentation", description: "Documentation (TEST-NET-2)", reference: "RFC 5737" },
  { cidr: "203.0.113.0/24", scope: "documentation", description: "Documentation (TEST-NET-3)", reference: "RFC 5737" },
  { cidr: "224.0.0.0/4", scope: "multicast", description: "Multicast", reference: "RFC 5771" },
  { cidr: "255.255.255.255/32", scope: "broadcast", description: "Limited broadcast", reference: "RFC 919" },
  { cidr: "240.0.0.0/4", scope: "reserved", description: "Reserved for future use", reference: "RFC 1112" },
];

const IPV6_RULES: RangeRule[] = [
  { cidr: "::/128", scope: "unspecified", description: "Unspecified address", reference: "RFC 4291" },
  { cidr: "::1/128", scope: "loopback", description: "Loopback", reference: "RFC 4291" },
  { cidr: "::ffff:0:0/96", scope: "ipv4-mapped", description: "IPv4-mapped address", reference: "RFC 4291" },
  { cidr: "64:ff9b::/96", scope: "translation", description: "IPv4/IPv6 translation (NAT64)", reference: "RFC 6052" },
  { cidr: "64:ff9b:1::/48", scope: "translation", description: "Local-use IPv4/IPv6 translation", reference: "RFC 8215" },
  { cidr: "100::/64", scope: "discard", description: "Discard-only prefix", reference: "RFC 6666" },
  { cidr: "2001::/23", scope: "protocol-assignment", description: "IETF protocol assignments", reference: "RFC 2928" },
  { cidr: "2001:db8::/32", scope: "documentation", description: "Documentation", reference: "RFC 3849" },
  { cidr: "2002::/16", scope: "translation", description: "6to4", reference: "RFC 3056" },
  { cidr: "3fff::/20", scope: "documentation", description: "Documentation", reference: "RFC 9637" },
  { cidr: "5f00::/16", scope: "reserved", description: "Segment routing SIDs", reference: "RFC 9602" },
  { cidr: "fc00::/7", scope: "unique-local", description: "Unique local address", reference: "RFC 4193" },
  { cidr: "fe80::/10", scope: "link-local", description: "Link-local unicast", reference: "RFC 4291" },
  { cidr: "fec0::/10", scope: "reserved", description: "Deprecated site-local", reference: "RFC 3879" },
  { cidr: "ff00::/8", scope: "multicast", description: "Multicast", reference: "RFC 4291" },
];

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIpv4(value: string): boolean {
  return IPV4_RE.test(value);
}

export function ipv4ToNumber(value: string): number {
  return value.split(".").reduce((acc, octet) => acc * 256 + Number(octet), 0);
}

/** Parses an IPv6 literal into a 128-bit bigint, or null when invalid. */
export function parseIpv6(input: string): bigint | null {
  let value = input.trim().toLowerCase();
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  if (!value.includes(":") || value.includes("%")) return null;
  if (!/^[0-9a-f:.]+$/.test(value)) return null;

  let embedded: number[] = [];
  const lastColon = value.lastIndexOf(":");
  const tail = value.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (!isIpv4(tail)) return null;
    const n = ipv4ToNumber(tail);
    embedded = [(n >>> 16) & 0xffff, n & 0xffff];
    value = value.slice(0, lastColon + 1) + "0:0";
  }

  const doubleColon = value.split("::");
  if (doubleColon.length > 2) return null;

  const parseGroups = (part: string) => (part === "" ? [] : part.split(":"));
  const head = parseGroups(doubleColon[0]);
  const rest = doubleColon.length === 2 ? parseGroups(doubleColon[1]) : [];
  if (doubleColon.length === 1 && head.length !== 8) return null;
  if (doubleColon.length === 2 && head.length + rest.length > 7) return null;

  const groups = [...head, ...Array(8 - head.length - rest.length).fill("0"), ...rest];
  if (groups.length !== 8) return null;

  let result = BigInt(0);
  for (let i = 0; i < 8; i++) {
    let group = groups[i];
    if (embedded.length && i >= 6) group = embedded[i - 6].toString(16);
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    result = (result << BigInt(16)) | BigInt(parseInt(group, 16));
  }
  return result;
}

export function isIpv6(value: string): boolean {
  return parseIpv6(value) !== null;
}

/** RFC 5952 canonical text form. */
export function formatIpv6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & BigInt(0xffff)));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(":");
  const left = hex.slice(0, bestStart).join(":");
  const right = hex.slice(bestStart + bestLen).join(":");
  return `${left}::${right}`;
}

export function normalizeIpv6(value: string): string | null {
  const parsed = parseIpv6(value);
  return parsed === null ? null : formatIpv6(parsed);
}

function matchV4(address: number, cidr: string): boolean {
  const [base, bits] = cidr.split("/");
  const prefix = Number(bits);
  if (prefix === 0) return true;
  const mask = prefix === 32 ? 0xffffffff : (~0 << (32 - prefix)) >>> 0;
  return ((address & mask) >>> 0) === ((ipv4ToNumber(base) & mask) >>> 0);
}

function matchV6(address: bigint, cidr: string): boolean {
  const [base, bits] = cidr.split("/");
  const prefix = BigInt(Number(bits));
  const baseValue = parseIpv6(base);
  if (baseValue === null) return false;
  if (prefix === BigInt(0)) return true;
  const shift = BigInt(128) - prefix;
  return address >> shift === baseValue >> shift;
}

function numberToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export function classifyIp(input: string): IpClassification | null {
  const value = input.trim();
  if (isIpv4(value)) {
    const n = ipv4ToNumber(value);
    const rule = IPV4_RULES.find((r) => matchV4(n, r.cidr));
    return rule
      ? { version: 4, address: value, scope: rule.scope, range: rule.cidr, description: rule.description, reference: rule.reference }
      : { version: 4, address: value, scope: "public", description: "Globally routable unicast address" };
  }

  const v6 = parseIpv6(value);
  if (v6 === null) return null;
  const address = formatIpv6(v6);
  const rule = IPV6_RULES.find((r) => matchV6(v6, r.cidr));
  const classification: IpClassification = rule
    ? { version: 6, address, scope: rule.scope, range: rule.cidr, description: rule.description, reference: rule.reference }
    : { version: 6, address, scope: "public", description: "Global unicast address" };

  if (rule?.scope === "ipv4-mapped" || rule?.cidr === "64:ff9b::/96") {
    classification.embeddedIpv4 = numberToIpv4(Number(v6 & BigInt(0xffffffff)));
  } else if (rule?.cidr === "2002::/16") {
    classification.embeddedIpv4 = numberToIpv4(Number((v6 >> BigInt(80)) & BigInt(0xffffffff)));
  }
  return classification;
}

/**
 * Whether a destination address is safe for the server to connect to. Anything
 * that is not plain public unicast is refused, including IPv4-mapped, NAT64 and
 * 6to4 forms that could tunnel to arbitrary IPv4 space.
 */
export function isPublicAddress(input: string): boolean {
  return classifyIp(input)?.scope === "public";
}

/** Reverse-DNS query name (in-addr.arpa / ip6.arpa) for an address. */
export function reverseDnsName(input: string): string | null {
  if (isIpv4(input)) return `${input.split(".").reverse().join(".")}.in-addr.arpa`;
  const v6 = parseIpv6(input);
  if (v6 === null) return null;
  const nibbles = v6.toString(16).padStart(32, "0").split("").reverse().join(".");
  return `${nibbles}.ip6.arpa`;
}
