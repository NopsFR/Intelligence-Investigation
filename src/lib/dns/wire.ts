// Minimal RFC 1035 message codec for DNS-over-HTTPS (RFC 8484) wire format.
// Supports name compression, EDNS(0) with the DO bit, and presentation-format
// rendering for the record types NOPS analyses.

import { formatIpv6 } from "@/lib/observables/ip";

export const RR_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  HTTPS: 65,
  CAA: 257,
} as const;

export type RecordType = keyof typeof RR_TYPES;
const TYPE_NAMES = new Map<number, RecordType>(Object.entries(RR_TYPES).map(([k, v]) => [v, k as RecordType]));

export function typeName(code: number): string {
  return TYPE_NAMES.get(code) ?? `TYPE${code}`;
}

export interface WireRecord {
  name: string;
  type: string;
  typeCode: number;
  class: number;
  ttl: number;
  data: string;
}

export interface WireMessage {
  id: number;
  flags: { qr: boolean; aa: boolean; tc: boolean; rd: boolean; ra: boolean; ad: boolean; cd: boolean };
  rcode: number;
  questions: { name: string; type: string }[];
  answers: WireRecord[];
  authority: WireRecord[];
  additional: WireRecord[];
}

export function encodeQuery(name: string, type: RecordType | number, options: { id?: number; dnssecOk?: boolean } = {}): Uint8Array {
  const typeCode = typeof type === "number" ? type : RR_TYPES[type];
  const labels = name.replace(/\.$/, "").split(".").filter(Boolean);
  const nameBytes: number[] = [];
  for (const label of labels) {
    const bytes = new TextEncoder().encode(label);
    if (bytes.length > 63) throw new Error(`Label too long: ${label}`);
    nameBytes.push(bytes.length, ...bytes);
  }
  nameBytes.push(0);

  const id = options.id ?? 0;
  const header = [id >> 8, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
  const question = [...nameBytes, typeCode >> 8, typeCode & 0xff, 0x00, 0x01];
  // OPT pseudo-record: root name, type 41, UDP payload 1232, extended RCODE 0, version 0, DO flag.
  const opt = [0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, options.dnssecOk === false ? 0x00 : 0x80, 0x00, 0x00, 0x00];
  return new Uint8Array([...header, ...question, ...opt]);
}

class Reader {
  offset = 0;
  constructor(public readonly buf: Uint8Array) {}
  u8() {
    if (this.offset + 1 > this.buf.length) throw new Error("Truncated DNS message");
    return this.buf[this.offset++];
  }
  u16() {
    return (this.u8() << 8) | this.u8();
  }
  u32() {
    return ((this.u16() << 16) >>> 0) + this.u16();
  }
  bytes(n: number) {
    if (this.offset + n > this.buf.length) throw new Error("Truncated DNS message");
    const out = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }
}

function readName(buf: Uint8Array, start: number): { name: string; next: number } {
  const labels: string[] = [];
  let offset = start;
  let next = -1;
  let jumps = 0;
  for (;;) {
    if (offset >= buf.length) throw new Error("Name exceeds message bounds");
    const len = buf[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= buf.length) throw new Error("Truncated compression pointer");
      const pointer = ((len & 0x3f) << 8) | buf[offset + 1];
      if (next === -1) next = offset + 2;
      if (++jumps > 32) throw new Error("Compression loop");
      offset = pointer;
      continue;
    }
    if ((len & 0xc0) !== 0) throw new Error("Unsupported label type");
    const label = buf.subarray(offset + 1, offset + 1 + len);
    labels.push(new TextDecoder().decode(label));
    offset += 1 + len;
  }
  return { name: labels.length ? `${labels.join(".")}.` : ".", next: next === -1 ? offset : next };
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function characterStrings(rdata: Uint8Array): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < rdata.length) {
    const len = rdata[i];
    out.push(new TextDecoder().decode(rdata.subarray(i + 1, i + 1 + len)));
    i += 1 + len;
  }
  return out;
}

function renderRdata(buf: Uint8Array, typeCode: number, start: number, length: number): string {
  const rdata = buf.subarray(start, start + length);
  const type = TYPE_NAMES.get(typeCode);
  switch (type) {
    case "A":
      return Array.from(rdata).join(".");
    case "AAAA": {
      let value = BigInt(0);
      for (const byte of rdata) value = (value << BigInt(8)) | BigInt(byte);
      return formatIpv6(value);
    }
    case "NS":
    case "CNAME":
    case "PTR":
      return readName(buf, start).name;
    case "MX": {
      const pref = (rdata[0] << 8) | rdata[1];
      return `${pref} ${readName(buf, start + 2).name}`;
    }
    case "TXT":
      return characterStrings(rdata).join("");
    case "SOA": {
      const mname = readName(buf, start);
      const rname = readName(buf, mname.next);
      const r = new Reader(buf);
      r.offset = rname.next;
      return `${mname.name} ${rname.name} ${r.u32()} ${r.u32()} ${r.u32()} ${r.u32()} ${r.u32()}`;
    }
    case "CAA": {
      const flags = rdata[0];
      const tagLen = rdata[1];
      const tag = new TextDecoder().decode(rdata.subarray(2, 2 + tagLen));
      const value = new TextDecoder().decode(rdata.subarray(2 + tagLen));
      return `${flags} ${tag} "${value}"`;
    }
    case "DS": {
      const keyTag = (rdata[0] << 8) | rdata[1];
      return `${keyTag} ${rdata[2]} ${rdata[3]} ${toHex(rdata.subarray(4))}`;
    }
    case "DNSKEY": {
      const flags = (rdata[0] << 8) | rdata[1];
      return `${flags} ${rdata[2]} ${rdata[3]} ${toBase64(rdata.subarray(4))}`;
    }
    case "RRSIG": {
      const covered = typeName((rdata[0] << 8) | rdata[1]);
      const r = new Reader(rdata);
      r.offset = 4;
      const originalTtl = r.u32();
      const expiration = r.u32();
      const inception = r.u32();
      const keyTag = r.u16();
      const signer = readName(buf, start + 18).name;
      return `${covered} ${rdata[2]} ${rdata[3]} ${originalTtl} ${expiration} ${inception} ${keyTag} ${signer}`;
    }
    default:
      return `\\# ${length} ${toHex(rdata)}`;
  }
}

function readRecord(reader: Reader): WireRecord {
  const { name, next } = readName(reader.buf, reader.offset);
  reader.offset = next;
  const typeCode = reader.u16();
  const cls = reader.u16();
  const ttl = reader.u32();
  const rdlength = reader.u16();
  const start = reader.offset;
  reader.bytes(rdlength);
  return {
    name,
    type: typeName(typeCode),
    typeCode,
    class: cls,
    ttl,
    data: typeCode === 41 ? "" : renderRdata(reader.buf, typeCode, start, rdlength),
  };
}

export function decodeMessage(input: Uint8Array): WireMessage {
  const reader = new Reader(input);
  const id = reader.u16();
  const flags = reader.u16();
  const qd = reader.u16();
  const an = reader.u16();
  const ns = reader.u16();
  const ar = reader.u16();
  const questions: WireMessage["questions"] = [];
  for (let i = 0; i < qd; i++) {
    const { name, next } = readName(input, reader.offset);
    reader.offset = next;
    const type = typeName(reader.u16());
    reader.u16();
    questions.push({ name, type });
  }
  const section = (count: number) => Array.from({ length: count }, () => readRecord(reader));
  const answers = section(an);
  const authority = section(ns);
  const additional = section(ar).filter((r) => r.typeCode !== 41);
  return {
    id,
    flags: {
      qr: Boolean(flags & 0x8000),
      aa: Boolean(flags & 0x0400),
      tc: Boolean(flags & 0x0200),
      rd: Boolean(flags & 0x0100),
      ra: Boolean(flags & 0x0080),
      ad: Boolean(flags & 0x0020),
      cd: Boolean(flags & 0x0010),
    },
    rcode: flags & 0x000f,
    questions,
    answers,
    authority,
    additional,
  };
}

export const RCODE_NAMES: Record<number, string> = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
};

export function base64UrlEncode(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
