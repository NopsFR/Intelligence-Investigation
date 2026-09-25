import { ParseError, Reader } from "@/lib/analysis/bytes";
import { formatIpv6 } from "@/lib/observables/ip";

export const DNS_TYPES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  35: "NAPTR",
  41: "OPT",
  43: "DS",
  46: "RRSIG",
  47: "NSEC",
  48: "DNSKEY",
  64: "SVCB",
  65: "HTTPS",
  99: "SPF",
  255: "ANY",
  257: "CAA",
};

export const RCODES = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"];

export interface DnsRecord {
  name: string;
  type: string;
  ttl: number;
  data: string;
}

export interface DnsMessage {
  id: number;
  response: boolean;
  opcode: number;
  rcode: string;
  flags: string[];
  questions: { name: string; type: string }[];
  answers: DnsRecord[];
  authority: DnsRecord[];
  additional: DnsRecord[];
}

function readName(r: Reader, start: number): { name: string; end: number } {
  const labels: string[] = [];
  let o = start;
  let end = -1;
  for (let jumps = 0; jumps < 32; ) {
    const len = r.u8(o);
    if (len === 0) {
      if (end < 0) end = o + 1;
      return { name: labels.join(".") || ".", end };
    }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | r.u8(o + 1);
      if (end < 0) end = o + 2;
      if (ptr >= r.length) throw new ParseError("DNS compression pointer out of range");
      o = ptr;
      jumps++;
      continue;
    }
    if (len > 63) throw new ParseError("Invalid DNS label length");
    const bytes = r.slice(o + 1, len);
    let s = "";
    for (const c of bytes) s += c > 0x20 && c < 0x7f && c !== 0x2e ? String.fromCharCode(c) : `\\${c.toString().padStart(3, "0")}`;
    labels.push(s);
    if (labels.length > 128) throw new ParseError("DNS name has too many labels");
    o += 1 + len;
  }
  throw new ParseError("DNS compression loop");
}

function readRecord(r: Reader, o: number): { rec: DnsRecord; end: number } {
  const { name, end } = readName(r, o);
  const type = r.u16(end);
  const ttl = r.u32(end + 4);
  const rdlen = r.u16(end + 8);
  const rd = end + 10;
  r.slice(rd, rdlen);
  let data = "";
  switch (type) {
    case 1:
      data = rdlen === 4 ? Array.from(r.slice(rd, 4)).join(".") : "";
      break;
    case 28: {
      if (rdlen === 16) {
        let v = BigInt(0);
        for (const c of r.slice(rd, 16)) v = (v << BigInt(8)) | BigInt(c);
        data = formatIpv6(v);
      }
      break;
    }
    case 2:
    case 5:
    case 12:
      data = readName(r, rd).name;
      break;
    case 15:
      data = `${r.u16(rd)} ${readName(r, rd + 2).name}`;
      break;
    case 33:
      data = `${r.u16(rd)} ${r.u16(rd + 2)} ${r.u16(rd + 4)} ${readName(r, rd + 6).name}`;
      break;
    case 6: {
      const m = readName(r, rd);
      const rn = readName(r, m.end);
      data = `${m.name} ${rn.name} serial ${r.u32(rn.end)}`;
      break;
    }
    case 16: {
      const parts: string[] = [];
      let p = rd;
      while (p < rd + rdlen && parts.length < 32) {
        const l = r.u8(p);
        parts.push(new TextDecoder("utf-8", { fatal: false }).decode(r.slice(p + 1, Math.min(l, rd + rdlen - p - 1))));
        p += 1 + l;
      }
      data = parts.join("");
      break;
    }
    default:
      data = `${rdlen} bytes`;
  }
  return { rec: { name, type: DNS_TYPES[type] ?? `TYPE${type}`, ttl, data }, end: rd + rdlen };
}

export function parseDns(bytes: Uint8Array): DnsMessage {
  const r = new Reader(bytes, false);
  if (bytes.length < 12) throw new ParseError("DNS message is shorter than its header");
  const flagsRaw = r.u16(2);
  const counts = [r.u16(4), r.u16(6), r.u16(8), r.u16(10)];
  if (counts.some((c) => c > 512)) throw new ParseError("Implausible DNS record counts");
  const flags: string[] = [];
  if (flagsRaw & 0x0400) flags.push("AA");
  if (flagsRaw & 0x0200) flags.push("TC");
  if (flagsRaw & 0x0100) flags.push("RD");
  if (flagsRaw & 0x0080) flags.push("RA");
  if (flagsRaw & 0x0020) flags.push("AD");
  if (flagsRaw & 0x0010) flags.push("CD");
  const msg: DnsMessage = { id: r.u16(0), response: (flagsRaw & 0x8000) !== 0, opcode: (flagsRaw >> 11) & 0xf, rcode: RCODES[flagsRaw & 0xf] ?? `RCODE${flagsRaw & 0xf}`, flags, questions: [], answers: [], authority: [], additional: [] };
  let o = 12;
  for (let i = 0; i < counts[0]; i++) {
    const { name, end } = readName(r, o);
    msg.questions.push({ name, type: DNS_TYPES[r.u16(end)] ?? `TYPE${r.u16(end)}` });
    o = end + 4;
  }
  const sections: DnsRecord[][] = [msg.answers, msg.authority, msg.additional];
  for (let s = 0; s < 3; s++) {
    for (let i = 0; i < counts[s + 1]; i++) {
      try {
        const { rec, end } = readRecord(r, o);
        if (rec.type !== "OPT") sections[s].push(rec);
        o = end;
      } catch {
        return msg; // keep what parsed
      }
    }
  }
  return msg;
}
