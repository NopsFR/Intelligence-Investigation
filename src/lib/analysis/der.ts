import { ParseError, hex } from "./bytes";

// Minimal DER (ASN.1) reader and X.509 walker. Enough to read certificates
// embedded in Authenticode signatures, TLS handshakes and PEM files. Nothing
// here verifies a signature or a chain: callers must say so.

export interface Asn1 {
  tag: number;
  cls: "universal" | "application" | "context" | "private";
  constructed: boolean;
  offset: number;
  headerLength: number;
  length: number;
  bytes: Uint8Array;
  children?: Asn1[];
}

const CLASSES = ["universal", "application", "context", "private"] as const;
const MAX_DEPTH = 32;
const MAX_NODES = 20_000;

/** Parse one DER element at `offset`. Children are parsed eagerly for constructed types. */
export function parseDer(input: Uint8Array, offset = 0): Asn1 {
  const budget = { nodes: 0 };
  return parseAt(input, offset, input.length, 0, budget);
}

function parseAt(b: Uint8Array, offset: number, end: number, depth: number, budget: { nodes: number }): Asn1 {
  if (depth > MAX_DEPTH) throw new ParseError("ASN.1 nesting is too deep");
  if (++budget.nodes > MAX_NODES) throw new ParseError("ASN.1 structure has too many elements");
  if (offset + 2 > end) throw new ParseError(`ASN.1 element at 0x${offset.toString(16)} is truncated`);
  const first = b[offset];
  const cls = CLASSES[first >> 6];
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (let i = 0; i < 4; i++) {
      if (p >= end) throw new ParseError("ASN.1 tag is truncated");
      const c = b[p++];
      tag = (tag << 7) | (c & 0x7f);
      if (!(c & 0x80)) break;
    }
  }
  if (p >= end) throw new ParseError("ASN.1 length is truncated");
  let length = b[p++];
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 4) throw new ParseError("Unsupported ASN.1 length form (indefinite or over 4 bytes)");
    length = 0;
    for (let i = 0; i < n; i++) {
      if (p >= end) throw new ParseError("ASN.1 length is truncated");
      length = length * 256 + b[p++];
    }
  }
  const headerLength = p - offset;
  if (p + length > end) throw new ParseError(`ASN.1 element at 0x${offset.toString(16)} runs past its container`);
  const node: Asn1 = { tag, cls, constructed, offset, headerLength, length, bytes: b.subarray(p, p + length) };
  if (constructed) {
    node.children = [];
    let q = p;
    while (q < p + length) {
      const child = parseAt(b, q, p + length, depth + 1, budget);
      node.children.push(child);
      q = child.offset + child.headerLength + child.length;
    }
  }
  return node;
}

/** The full encoding (header + content) of a node, as a view into the source. */
export function encoded(source: Uint8Array, node: Asn1): Uint8Array {
  return source.subarray(node.offset, node.offset + node.headerLength + node.length);
}

export function oid(node: Asn1): string {
  const b = node.bytes;
  if (!b.length) return "";
  const parts: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  if (b[0] >= 80) {
    parts[0] = 2;
    parts[1] = b[0] - 80;
  }
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

export function integerHex(node: Asn1): string {
  let b = node.bytes;
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  return hex(b);
}

export function integerValue(node: Asn1): number {
  let v = 0;
  for (const c of node.bytes.subarray(0, 6)) v = v * 256 + c;
  return v;
}

export function text(node: Asn1): string {
  const b = node.bytes;
  if (node.tag === 0x1e) {
    // BMPString (UTF-16BE)
    let s = "";
    for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
    return s;
  }
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(b);
  } catch {
    return Array.from(b, (c) => String.fromCharCode(c)).join("");
  }
}

export function time(node: Asn1): string | null {
  const s = text(node);
  // UTCTime YYMMDDHHMMSSZ, GeneralizedTime YYYYMMDDHHMMSSZ
  const m = node.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/.exec(s);
  if (!m) return null;
  let year = Number(m[1]);
  if (node.tag === 0x17) year += year < 50 ? 2000 : 1900;
  const d = new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export const OID_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "C",
  "2.5.4.7": "L",
  "2.5.4.8": "ST",
  "2.5.4.9": "street",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
  "2.5.4.15": "businessCategory",
  "2.5.4.97": "organizationIdentifier",
  "1.2.840.113549.1.9.1": "emailAddress",
  "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
  "0.9.2342.19200300.100.1.25": "DC",
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.113549.1.1.4": "md5WithRSA",
  "1.2.840.113549.1.1.5": "sha1WithRSA",
  "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.113549.1.1.11": "sha256WithRSA",
  "1.2.840.113549.1.1.12": "sha384WithRSA",
  "1.2.840.113549.1.1.13": "sha512WithRSA",
  "1.2.840.10045.2.1": "EC",
  "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
  "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
  "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
  "1.3.101.112": "Ed25519",
  "1.3.14.3.2.26": "SHA-1",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
  "1.2.840.113549.2.5": "MD5",
  "1.2.840.113549.1.7.1": "data",
  "1.2.840.113549.1.7.2": "signedData",
  "1.2.840.113549.1.9.3": "contentType",
  "1.2.840.113549.1.9.4": "messageDigest",
  "1.2.840.113549.1.9.5": "signingTime",
  "1.2.840.113549.1.9.6": "counterSignature",
  "1.2.840.113549.1.9.16.2.14": "timeStampToken",
  "1.3.6.1.4.1.311.3.3.1": "msTimestamp",
  "1.3.6.1.4.1.311.2.1.4": "SpcIndirectDataContent",
  "1.3.6.1.4.1.311.2.1.12": "SpcSpOpusInfo",
  "1.3.6.1.4.1.311.2.1.15": "SpcPeImageData",
  "1.3.6.1.4.1.311.2.4.1": "nestedSignature",
  "2.5.29.14": "subjectKeyIdentifier",
  "2.5.29.15": "keyUsage",
  "2.5.29.17": "subjectAltName",
  "2.5.29.19": "basicConstraints",
  "2.5.29.31": "cRLDistributionPoints",
  "2.5.29.32": "certificatePolicies",
  "2.5.29.35": "authorityKeyIdentifier",
  "2.5.29.37": "extKeyUsage",
  "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
  "1.3.6.1.4.1.11129.2.4.2": "ctPrecertificateSCTs",
  "1.3.6.1.5.5.7.3.1": "serverAuth",
  "1.3.6.1.5.5.7.3.2": "clientAuth",
  "1.3.6.1.5.5.7.3.3": "codeSigning",
  "1.3.6.1.5.5.7.3.4": "emailProtection",
  "1.3.6.1.5.5.7.3.8": "timeStamping",
};

export const oidName = (o: string) => OID_NAMES[o] ?? o;

export interface DistinguishedName {
  text: string;
  attributes: { type: string; value: string }[];
  cn?: string;
  o?: string;
}

export function distinguishedName(node: Asn1 | undefined): DistinguishedName {
  const attributes: { type: string; value: string }[] = [];
  for (const rdn of node?.children ?? []) {
    for (const atv of rdn.children ?? []) {
      const [type, value] = atv.children ?? [];
      if (type && value) attributes.push({ type: oidName(oid(type)), value: text(value) });
    }
  }
  const find = (t: string) => attributes.find((a) => a.type === t)?.value;
  return { attributes, text: attributes.map((a) => `${a.type}=${a.value}`).join(", "), cn: find("CN"), o: find("O") };
}

export interface Certificate {
  version: number;
  serial: string;
  signatureAlgorithm: string;
  issuer: DistinguishedName;
  subject: DistinguishedName;
  notBefore: string | null;
  notAfter: string | null;
  publicKey: { algorithm: string; bits?: number; curve?: string };
  subjectAltNames: string[];
  extendedKeyUsage: string[];
  isCA: boolean | null;
  selfIssued: boolean;
  /** Full DER encoding, for fingerprints. */
  der: Uint8Array;
}

function rsaBits(spki: Asn1): number | undefined {
  try {
    const bitString = spki.children?.[1];
    if (!bitString) return undefined;
    const inner = parseDer(bitString.bytes.subarray(1));
    const modulus = inner.children?.[0];
    if (!modulus) return undefined;
    let m = modulus.bytes;
    while (m.length > 1 && m[0] === 0) m = m.subarray(1);
    return m.length * 8 - Math.clz32(m[0]) + 24;
  } catch {
    return undefined;
  }
}

export function parseCertificate(source: Uint8Array, node?: Asn1): Certificate {
  const cert = node ?? parseDer(source);
  const tbs = cert.children?.[0];
  if (!tbs?.children) throw new ParseError("Not an X.509 certificate");
  let i = 0;
  let version = 1;
  if (tbs.children[0].cls === "context" && tbs.children[0].tag === 0) {
    version = integerValue(tbs.children[0].children![0]) + 1;
    i = 1;
  }
  const serial = integerHex(tbs.children[i]);
  const sigAlg = oidName(oid(tbs.children[i + 1].children![0]));
  const issuer = distinguishedName(tbs.children[i + 2]);
  const validity = tbs.children[i + 3].children ?? [];
  const subject = distinguishedName(tbs.children[i + 4]);
  const spki = tbs.children[i + 5];
  const keyAlgNode = spki.children?.[0]?.children;
  const keyAlg = keyAlgNode?.[0] ? oidName(oid(keyAlgNode[0])) : "unknown";
  const curve = keyAlgNode?.[1] && keyAlgNode[1].tag === 6 ? oidName(oid(keyAlgNode[1])) : undefined;

  const sans: string[] = [];
  const eku: string[] = [];
  let isCA: boolean | null = null;
  const extWrapper = tbs.children.slice(i + 6).find((c) => c.cls === "context" && c.tag === 3);
  for (const ext of extWrapper?.children?.[0]?.children ?? []) {
    const extId = oid(ext.children![0]);
    const valueNode = ext.children![ext.children!.length - 1];
    try {
      const value = parseDer(valueNode.bytes);
      if (extId === "2.5.29.17") {
        for (const gn of value.children ?? []) {
          if (gn.cls !== "context") continue;
          if (gn.tag === 2 || gn.tag === 1 || gn.tag === 6) sans.push(text(gn));
          else if (gn.tag === 7) sans.push(gn.bytes.length === 4 ? Array.from(gn.bytes).join(".") : hex(gn.bytes, ":"));
        }
      } else if (extId === "2.5.29.37") {
        for (const k of value.children ?? []) eku.push(oidName(oid(k)));
      } else if (extId === "2.5.29.19") {
        isCA = value.children?.[0]?.tag === 1 ? value.children[0].bytes[0] !== 0 : false;
      }
    } catch {
      // A malformed extension does not invalidate the rest of the certificate.
    }
  }

  return {
    version,
    serial,
    signatureAlgorithm: sigAlg,
    issuer,
    subject,
    notBefore: validity[0] ? time(validity[0]) : null,
    notAfter: validity[1] ? time(validity[1]) : null,
    publicKey: { algorithm: keyAlg, bits: keyAlg === "RSA" ? rsaBits(spki) : undefined, curve },
    subjectAltNames: sans,
    extendedKeyUsage: eku,
    isCA,
    selfIssued: issuer.text === subject.text,
    der: encoded(source, cert),
  };
}

/** Certificates from PEM text (any number of CERTIFICATE blocks). */
export function certificatesFromPem(pem: string): Certificate[] {
  const out: Certificate[] = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  for (const m of pem.matchAll(re)) {
    const b64 = m[1].replace(/\s+/g, "");
    const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    out.push(parseCertificate(bin));
    if (out.length >= 50) break;
  }
  return out;
}
