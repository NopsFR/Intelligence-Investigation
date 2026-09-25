import { ParseError, Reader } from "@/lib/analysis/bytes";
import { parseCertificate, type Certificate } from "@/lib/analysis/der";
import { md5, sha256Sync } from "@/lib/analysis/hash";

// TLS handshake parsing for passive analysis: ClientHello / ServerHello
// fields, JA3 / JA3S / JA4 fingerprints and (TLS ≤ 1.2) server certificates.

export const TLS_VERSIONS: Record<number, string> = { 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3", 0xfeff: "DTLS 1.0", 0xfefd: "DTLS 1.2", 0xfefc: "DTLS 1.3" };

export const CIPHER_NAMES: Record<number, string> = {
  0x1301: "TLS_AES_128_GCM_SHA256",
  0x1302: "TLS_AES_256_GCM_SHA384",
  0x1303: "TLS_CHACHA20_POLY1305_SHA256",
  0xc02b: "ECDHE_ECDSA_AES_128_GCM_SHA256",
  0xc02f: "ECDHE_RSA_AES_128_GCM_SHA256",
  0xc02c: "ECDHE_ECDSA_AES_256_GCM_SHA384",
  0xc030: "ECDHE_RSA_AES_256_GCM_SHA384",
  0xcca9: "ECDHE_ECDSA_CHACHA20_POLY1305",
  0xcca8: "ECDHE_RSA_CHACHA20_POLY1305",
  0xc013: "ECDHE_RSA_AES_128_CBC_SHA",
  0xc014: "ECDHE_RSA_AES_256_CBC_SHA",
  0x009c: "RSA_AES_128_GCM_SHA256",
  0x009d: "RSA_AES_256_GCM_SHA384",
  0x002f: "RSA_AES_128_CBC_SHA",
  0x0035: "RSA_AES_256_CBC_SHA",
  0x000a: "RSA_3DES_EDE_CBC_SHA",
  0x0005: "RSA_RC4_128_SHA",
  0x0004: "RSA_RC4_128_MD5",
  0x00ff: "EMPTY_RENEGOTIATION_INFO_SCSV",
};

export const EXTENSION_NAMES: Record<number, string> = {
  0: "server_name",
  5: "status_request",
  10: "supported_groups",
  11: "ec_point_formats",
  13: "signature_algorithms",
  16: "alpn",
  18: "signed_certificate_timestamp",
  21: "padding",
  23: "extended_master_secret",
  27: "compress_certificate",
  35: "session_ticket",
  41: "pre_shared_key",
  43: "supported_versions",
  45: "psk_key_exchange_modes",
  51: "key_share",
  17513: "application_settings",
  65037: "encrypted_client_hello",
  65281: "renegotiation_info",
};

export const isGrease = (v: number) => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);

export interface ClientHello {
  version: number;
  ciphers: number[];
  extensions: number[];
  sni?: string;
  alpn: string[];
  groups: number[];
  pointFormats: number[];
  signatureAlgorithms: number[];
  supportedVersions: number[];
  ja3: string;
  ja3Hash: string;
  ja4: string;
  ja4Raw: string;
  ech: boolean;
}

export interface ServerHello {
  version: number;
  cipher: number;
  extensions: number[];
  selectedVersion?: number;
  alpn?: string;
  ja3s: string;
  ja3sHash: string;
}

export interface TlsHandshake {
  clientHello?: ClientHello;
  serverHello?: ServerHello;
  certificates: Certificate[];
  alerts: { level: number; description: number }[];
  records: number;
  encrypted: boolean;
}

const JA4_VERSION: Record<number, string> = { 0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3" };
const hex4 = (n: number) => n.toString(16).padStart(4, "0");
const alnum = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);

function ja4(ch: Omit<ClientHello, "ja4" | "ja4Raw" | "ja3" | "ja3Hash">, transport: "t" | "q"): { ja4: string; raw: string } {
  const versions = ch.supportedVersions.filter((v) => !isGrease(v));
  const version = versions.length ? Math.max(...versions) : ch.version;
  const ciphers = ch.ciphers.filter((c) => !isGrease(c));
  const exts = ch.extensions.filter((e) => !isGrease(e));
  let alpn = "00";
  const first = ch.alpn[0];
  if (first) {
    const b = new TextEncoder().encode(first);
    const a = b[0];
    const z = b[b.length - 1];
    if (alnum(a) && alnum(z)) alpn = String.fromCharCode(a) + String.fromCharCode(z);
    else {
      const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
      alpn = h[0] + h[h.length - 1];
    }
  }
  const a = `${transport}${JA4_VERSION[version] ?? "00"}${ch.sni ? "d" : "i"}${String(Math.min(ciphers.length, 99)).padStart(2, "0")}${String(Math.min(exts.length, 99)).padStart(2, "0")}${alpn}`;
  const cipherList = ciphers.map(hex4).sort().join(",");
  const extList = exts.filter((e) => e !== 0 && e !== 16).map(hex4).sort().join(",");
  const sigs = ch.signatureAlgorithms.filter((s) => !isGrease(s)).map(hex4).join(",");
  const cPart = sigs ? `${extList}_${sigs}` : extList;
  const trunc = (s: string) => (s ? sha256Sync(new TextEncoder().encode(s)).slice(0, 12) : "000000000000");
  return { ja4: `${a}_${ciphers.length ? trunc(cipherList) : "000000000000"}_${trunc(cPart)}`, raw: `${a}_${cipherList}_${cPart}` };
}

export function parseClientHello(body: Uint8Array, transport: "t" | "q" = "t"): ClientHello {
  const r = new Reader(body, false);
  const version = r.u16(0);
  let o = 34;
  o += 1 + r.u8(o); // session id
  const cipherLen = r.u16(o);
  const ciphers: number[] = [];
  for (let i = 0; i < cipherLen; i += 2) ciphers.push(r.u16(o + 2 + i));
  o += 2 + cipherLen;
  o += 1 + r.u8(o); // compression methods
  const extensions: number[] = [];
  let sni: string | undefined;
  const alpn: string[] = [];
  const groups: number[] = [];
  const pointFormats: number[] = [];
  const signatureAlgorithms: number[] = [];
  const supportedVersions: number[] = [];
  let ech = false;
  if (o + 2 <= body.length) {
    const extEnd = Math.min(body.length, o + 2 + r.u16(o));
    o += 2;
    while (o + 4 <= extEnd && extensions.length < 128) {
      const type = r.u16(o);
      const len = r.u16(o + 2);
      const d = o + 4;
      if (d + len > extEnd) break;
      extensions.push(type);
      try {
        if (type === 0 && len >= 5) {
          const nameLen = r.u16(d + 3);
          sni = new TextDecoder().decode(r.slice(d + 5, nameLen));
        } else if (type === 16) {
          let p = d + 2;
          while (p < d + len) {
            const l = r.u8(p);
            alpn.push(new TextDecoder().decode(r.slice(p + 1, l)));
            p += 1 + l;
          }
        } else if (type === 10) {
          for (let i = 0; i < r.u16(d); i += 2) groups.push(r.u16(d + 2 + i));
        } else if (type === 11) {
          for (let i = 0; i < r.u8(d); i++) pointFormats.push(r.u8(d + 1 + i));
        } else if (type === 13) {
          for (let i = 0; i < r.u16(d); i += 2) signatureAlgorithms.push(r.u16(d + 2 + i));
        } else if (type === 43) {
          for (let i = 0; i < r.u8(d); i += 2) supportedVersions.push(r.u16(d + 1 + i));
        } else if (type === 65037) ech = true;
      } catch {
        // A malformed extension body does not invalidate the hello.
      }
      o = d + len;
    }
  }
  const base = { version, ciphers, extensions, sni, alpn, groups, pointFormats, signatureAlgorithms, supportedVersions, ech };
  const noGrease = (l: number[]) => l.filter((v) => !isGrease(v)).join("-");
  const ja3 = `${version},${noGrease(ciphers)},${noGrease(extensions)},${noGrease(groups)},${pointFormats.join("-")}`;
  const j4 = ja4(base, transport);
  return { ...base, ja3, ja3Hash: md5(new TextEncoder().encode(ja3)), ja4: j4.ja4, ja4Raw: j4.raw };
}

export function parseServerHello(body: Uint8Array): ServerHello {
  const r = new Reader(body, false);
  const version = r.u16(0);
  let o = 34;
  o += 1 + r.u8(o);
  const cipher = r.u16(o);
  o += 3;
  const extensions: number[] = [];
  let selectedVersion: number | undefined;
  let alpn: string | undefined;
  if (o + 2 <= body.length) {
    const extEnd = Math.min(body.length, o + 2 + r.u16(o));
    o += 2;
    while (o + 4 <= extEnd && extensions.length < 64) {
      const type = r.u16(o);
      const len = r.u16(o + 2);
      extensions.push(type);
      try {
        if (type === 43 && len === 2) selectedVersion = r.u16(o + 4);
        if (type === 16 && len > 3) alpn = new TextDecoder().decode(r.slice(o + 7, r.u8(o + 6)));
      } catch {
        // ignore
      }
      o += 4 + len;
    }
  }
  const ja3s = `${version},${cipher},${extensions.join("-")}`;
  return { version, cipher, extensions, selectedVersion, alpn, ja3s, ja3sHash: md5(new TextEncoder().encode(ja3s)) };
}

function parseCertificateMessage(body: Uint8Array): Certificate[] {
  const out: Certificate[] = [];
  const r = new Reader(body, false);
  const total = (r.u8(0) << 16) | r.u16(1);
  let o = 3;
  const end = Math.min(body.length, 3 + total);
  while (o + 3 <= end && out.length < 10) {
    const len = (r.u8(o) << 16) | r.u16(o + 1);
    if (o + 3 + len > end) break;
    try {
      out.push(parseCertificate(body.subarray(o + 3, o + 3 + len)));
    } catch {
      // skip an unparseable certificate
    }
    o += 3 + len;
  }
  return out;
}

/** True when the bytes look like the start of a TLS record. */
export function looksLikeTls(b: Uint8Array): boolean {
  return b.length >= 6 && b[0] >= 20 && b[0] <= 24 && b[1] === 3 && b[2] <= 4;
}

/**
 * Parse a (reassembled) TLS byte stream from one direction: records, then
 * handshake messages that may span records. Stops at the first encrypted record.
 */
export function parseTlsStream(stream: Uint8Array, transport: "t" | "q" = "t"): TlsHandshake {
  const out: TlsHandshake = { certificates: [], alerts: [], records: 0, encrypted: false };
  const r = new Reader(stream, false);
  const hs: number[] = [];
  let hsBuf = new Uint8Array(0);
  let o = 0;
  let changeCipher = false;
  while (o + 5 <= stream.length && out.records < 4096) {
    const type = r.u8(o);
    const version = r.u16(o + 1);
    const len = r.u16(o + 3);
    if (type < 20 || type > 24 || version >> 8 !== 3) break;
    out.records++;
    const payload = stream.subarray(o + 5, Math.min(stream.length, o + 5 + len));
    if (type === 20) changeCipher = true;
    else if (type === 23) out.encrypted = true;
    else if (type === 21 && payload.length >= 2 && !changeCipher) out.alerts.push({ level: payload[0], description: payload[1] });
    else if (type === 22 && !changeCipher) {
      const merged = new Uint8Array(hsBuf.length + payload.length);
      merged.set(hsBuf);
      merged.set(payload, hsBuf.length);
      hsBuf = merged;
    }
    if (o + 5 + len > stream.length) break;
    o += 5 + len;
  }
  let p = 0;
  while (p + 4 <= hsBuf.length && hs.length < 32) {
    const t = hsBuf[p];
    const l = (hsBuf[p + 1] << 16) | (hsBuf[p + 2] << 8) | hsBuf[p + 3];
    if (p + 4 + l > hsBuf.length) break;
    const body = hsBuf.subarray(p + 4, p + 4 + l);
    hs.push(t);
    try {
      if (t === 1 && !out.clientHello) out.clientHello = parseClientHello(body, transport);
      else if (t === 2 && !out.serverHello) out.serverHello = parseServerHello(body);
      else if (t === 11 && !out.certificates.length) out.certificates = parseCertificateMessage(body);
    } catch (err) {
      if (!(err instanceof ParseError)) throw err;
    }
    p += 4 + l;
  }
  return out;
}

export const ALERTS: Record<number, string> = { 0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension", 112: "unrecognized_name", 116: "certificate_required", 120: "no_application_protocol" };
