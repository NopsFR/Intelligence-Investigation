// Byte-level helpers shared by the file, binary and packet parsers. Every read
// is bounds-checked: hostile input must fail with a clear error, never with an
// out-of-range read or an infinite loop.

export class ParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParseError";
  }
}

export class Reader {
  readonly view: DataView;
  constructor(
    readonly bytes: Uint8Array,
    public littleEndian = true
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  get length() {
    return this.bytes.length;
  }
  has(offset: number, size: number): boolean {
    return offset >= 0 && size >= 0 && offset + size <= this.bytes.length;
  }
  private check(offset: number, size: number, what: string) {
    if (!this.has(offset, size)) throw new ParseError(`${what} at 0x${offset.toString(16)} is outside the file (${this.bytes.length} bytes)`);
  }
  u8(o: number) {
    this.check(o, 1, "u8");
    return this.bytes[o];
  }
  u16(o: number, le = this.littleEndian) {
    this.check(o, 2, "u16");
    return this.view.getUint16(o, le);
  }
  u32(o: number, le = this.littleEndian) {
    this.check(o, 4, "u32");
    return this.view.getUint32(o, le);
  }
  i32(o: number, le = this.littleEndian) {
    this.check(o, 4, "i32");
    return this.view.getInt32(o, le);
  }
  u64(o: number, le = this.littleEndian): bigint {
    this.check(o, 8, "u64");
    return this.view.getBigUint64(o, le);
  }
  /** 64-bit value as a Number when it fits (offsets and sizes), else throws. */
  u64n(o: number, le = this.littleEndian): number {
    const v = this.u64(o, le);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ParseError(`64-bit value at 0x${o.toString(16)} is too large`);
    return Number(v);
  }
  slice(o: number, n: number) {
    this.check(o, n, "range");
    return this.bytes.subarray(o, o + n);
  }
  cstring(o: number, max = 512): string {
    if (o < 0 || o >= this.bytes.length) return "";
    let end = o;
    const limit = Math.min(this.bytes.length, o + max);
    while (end < limit && this.bytes[end] !== 0) end++;
    return latin1(this.bytes.subarray(o, end));
  }
  utf16(o: number, chars: number): string {
    const n = Math.max(0, Math.min(chars, Math.floor((this.bytes.length - o) / 2)));
    let s = "";
    for (let i = 0; i < n; i++) s += String.fromCharCode(this.view.getUint16(o + i * 2, true));
    return s;
  }
}

export function latin1(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

export function hex(bytes: Uint8Array, sep = ""): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(sep);
}

export function hexNum(n: number | bigint, pad = 0): string {
  return `0x${n.toString(16).padStart(pad, "0")}`;
}

/** Shannon entropy in bits per byte (0 – 8). */
export function entropy(bytes: Uint8Array, start = 0, end = bytes.length): number {
  const n = end - start;
  if (n <= 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = start; i < end; i++) counts[bytes[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Entropy over fixed windows — the profile shows packed or encrypted regions. */
export function entropyProfile(bytes: Uint8Array, buckets = 128): { offset: number; size: number; entropy: number }[] {
  if (!bytes.length) return [];
  const size = Math.max(256, Math.ceil(bytes.length / buckets));
  const out: { offset: number; size: number; entropy: number }[] = [];
  for (let o = 0; o < bytes.length; o += size) out.push({ offset: o, size: Math.min(size, bytes.length - o), entropy: entropy(bytes, o, Math.min(bytes.length, o + size)) });
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array | number[], offset = 0): boolean {
  if (offset + b.length > a.length) return false;
  for (let i = 0; i < b.length; i++) if (a[offset + i] !== b[i]) return false;
  return true;
}
