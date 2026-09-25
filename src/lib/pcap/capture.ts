import { ParseError, Reader } from "@/lib/analysis/bytes";

// pcap and pcapng container readers. They return frame boundaries and
// timestamps; decoding the frames is dissect.ts's job.

export const MAX_PACKETS = 500_000;

export interface RawFrame {
  index: number;
  /** Microseconds since the Unix epoch. */
  ts: number;
  offset: number;
  captured: number;
  original: number;
  linkType: number;
  interfaceId: number;
}

export interface CaptureFile {
  format: "pcap" | "pcapng";
  byteOrder: "little" | "big";
  nanosecond: boolean;
  snaplen?: number;
  interfaces: { linkType: number; name?: string; description?: string; tsresol: number }[];
  frames: RawFrame[];
  truncated: boolean;
  comments: string[];
  errors: string[];
}

export const LINK_TYPES: Record<number, string> = {
  0: "BSD loopback",
  1: "Ethernet",
  12: "Raw IP",
  101: "Raw IP",
  105: "IEEE 802.11",
  108: "OpenBSD loopback",
  113: "Linux cooked (SLL)",
  127: "802.11 radiotap",
  228: "Raw IPv4",
  229: "Raw IPv6",
  276: "Linux cooked v2 (SLL2)",
};

export function readCapture(bytes: Uint8Array): CaptureFile {
  if (bytes.length < 24) throw new ParseError("File is too small to be a capture");
  const magicLE = new Reader(bytes, true).u32(0);
  if (magicLE === 0x0a0d0d0a) return readPcapng(bytes);
  const variants: Record<number, [boolean, boolean]> = {
    0xa1b2c3d4: [true, false],
    0xd4c3b2a1: [false, false],
    0xa1b23c4d: [true, true],
    0x4d3cb2a1: [false, true],
  };
  const v = variants[magicLE];
  if (!v) throw new ParseError("Not a pcap or pcapng file (unknown magic number)");
  const [le, nano] = v;
  const r = new Reader(bytes, le);
  const snaplen = r.u32(16);
  const linkType = r.u32(20) & 0x0fffffff;
  const frames: RawFrame[] = [];
  const errors: string[] = [];
  let o = 24;
  let truncated = false;
  while (o + 16 <= bytes.length) {
    if (frames.length >= MAX_PACKETS) {
      truncated = true;
      break;
    }
    const sec = r.u32(o);
    const frac = r.u32(o + 4);
    const incl = r.u32(o + 8);
    const orig = r.u32(o + 12);
    if (incl > 0x40000 || (snaplen && incl > Math.max(snaplen, 0x40000))) {
      errors.push(`Record at 0x${o.toString(16)} claims ${incl} bytes; stopping (corrupt or truncated file)`);
      break;
    }
    if (o + 16 + incl > bytes.length) {
      errors.push(`Last record at 0x${o.toString(16)} is cut short (file truncated)`);
      break;
    }
    frames.push({ index: frames.length + 1, ts: sec * 1e6 + (nano ? Math.floor(frac / 1000) : frac), offset: o + 16, captured: incl, original: orig, linkType, interfaceId: 0 });
    o += 16 + incl;
  }
  return { format: "pcap", byteOrder: le ? "little" : "big", nanosecond: nano, snaplen, interfaces: [{ linkType, tsresol: nano ? 9 : 6 }], frames, truncated, comments: [], errors };
}

function readPcapng(bytes: Uint8Array): CaptureFile {
  const frames: RawFrame[] = [];
  const errors: string[] = [];
  const comments: string[] = [];
  let interfaces: CaptureFile["interfaces"] = [];
  let r = new Reader(bytes, true);
  let le = true;
  let o = 0;
  let truncated = false;
  const text = (off: number, len: number) => new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(off, off + len));

  const readOptions = (start: number, end: number, onOption: (code: number, off: number, len: number) => void) => {
    let p = start;
    for (let guard = 0; guard < 256 && p + 4 <= end; guard++) {
      const code = r.u16(p);
      const len = r.u16(p + 2);
      if (code === 0) break;
      if (p + 4 + len > end) break;
      onOption(code, p + 4, len);
      p += 4 + ((len + 3) & ~3);
    }
  };

  while (o + 12 <= bytes.length) {
    const type = r.u32(o);
    if (type === 0x0a0d0d0a) {
      // Section header: byte-order magic decides endianness for this section.
      const bom = new Reader(bytes, true).u32(o + 8);
      le = bom === 0x1a2b3c4d;
      if (!le && bom !== 0x4d3c2b1a) throw new ParseError("pcapng section header has an invalid byte-order magic");
      r = new Reader(bytes, le);
      interfaces = interfaces.length ? interfaces : [];
    }
    const len = r.u32(o + 4);
    if (len < 12 || len % 4 !== 0 || o + len > bytes.length) {
      errors.push(`Block at 0x${o.toString(16)} has an invalid length (${len}); stopping`);
      break;
    }
    if (type === 0x0a0d0d0a) {
      readOptions(o + 24, o + len - 4, (code, off, l) => code === 1 && comments.push(text(off, l)));
    } else if (type === 1) {
      const iface: CaptureFile["interfaces"][number] = { linkType: r.u16(o + 8), tsresol: 6 };
      readOptions(o + 16, o + len - 4, (code, off, l) => {
        if (code === 2) iface.name = text(off, l);
        else if (code === 3) iface.description = text(off, l);
        else if (code === 9 && l >= 1) iface.tsresol = bytes[off];
      });
      interfaces.push(iface);
    } else if (type === 6 || type === 3 || type === 2) {
      if (frames.length >= MAX_PACKETS) {
        truncated = true;
        break;
      }
      let ifaceId = 0;
      let ts = 0;
      let captured: number;
      let original: number;
      let dataOff: number;
      if (type === 6 || type === 2) {
        ifaceId = type === 6 ? r.u32(o + 8) : r.u16(o + 8);
        const hi = r.u32(o + 12);
        const lo = r.u32(o + 16);
        captured = r.u32(o + 20);
        original = r.u32(o + 24);
        dataOff = o + 28;
        const iface = interfaces[ifaceId];
        const res = iface?.tsresol ?? 6;
        const raw = hi * 4294967296 + lo;
        const perSecond = res & 0x80 ? 2 ** (res & 0x7f) : 10 ** res;
        ts = Math.floor((raw / perSecond) * 1e6);
      } else {
        original = r.u32(o + 8);
        captured = Math.min(original, len - 16);
        dataOff = o + 12;
      }
      if (dataOff + captured > o + len) {
        errors.push(`Packet block at 0x${o.toString(16)} is inconsistent; skipped`);
      } else {
        frames.push({ index: frames.length + 1, ts, offset: dataOff, captured, original, linkType: interfaces[ifaceId]?.linkType ?? 1, interfaceId: ifaceId });
      }
    }
    o += len;
  }
  if (!interfaces.length && frames.length) errors.push("No interface description block; assuming Ethernet");
  return { format: "pcapng", byteOrder: le ? "little" : "big", nanosecond: interfaces.some((i) => i.tsresol === 9), interfaces, frames, truncated, comments, errors };
}
