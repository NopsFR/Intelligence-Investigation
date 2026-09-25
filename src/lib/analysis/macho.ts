import { ParseError, Reader, entropy, hex, latin1 } from "./bytes";
import { parseCertificate, parseDer, type Certificate } from "./der";

// Mach-O static parser (thin and universal binaries): load commands,
// segments, linked libraries, symbols and the code-signature superblob.

const MAX_COMMANDS = 1024;
const MAX_SYMBOLS = 50_000;

const CPU: Record<number, string> = {
  7: "x86",
  0x01000007: "x86-64",
  12: "ARM",
  0x0100000c: "ARM64",
  0x0200000c: "ARM64_32",
  18: "PowerPC",
  0x01000012: "PowerPC 64",
};

const FILETYPES: Record<number, string> = {
  1: "Object",
  2: "Executable",
  3: "Fixed VM library",
  4: "Core dump",
  5: "Preloaded executable",
  6: "Dynamic library",
  7: "Dynamic linker",
  8: "Bundle",
  9: "Dynamic library stub",
  10: "Debug symbols (dSYM)",
  11: "Kernel extension",
  12: "File set",
};

const HEADER_FLAGS: [number, string][] = [
  [0x1, "NOUNDEFS"],
  [0x4, "DYLDLINK"],
  [0x80, "TWOLEVEL"],
  [0x20000, "ALLOW_STACK_EXECUTION"],
  [0x200000, "PIE"],
  [0x800000, "HAS_TLV_DESCRIPTORS"],
  [0x1000000, "NO_HEAP_EXECUTION"],
  [0x2000000, "APP_EXTENSION_SAFE"],
];

const LC: Record<number, string> = {
  0x1: "SEGMENT",
  0x2: "SYMTAB",
  0xb: "DYSYMTAB",
  0xc: "LOAD_DYLIB",
  0xd: "ID_DYLIB",
  0xe: "LOAD_DYLINKER",
  0x19: "SEGMENT_64",
  0x1b: "UUID",
  0x1d: "CODE_SIGNATURE",
  0x1e: "SEGMENT_SPLIT_INFO",
  0x20: "LAZY_LOAD_DYLIB",
  0x21: "ENCRYPTION_INFO",
  0x22: "DYLD_INFO",
  0x24: "VERSION_MIN_MACOSX",
  0x25: "VERSION_MIN_IPHONEOS",
  0x26: "FUNCTION_STARTS",
  0x29: "DATA_IN_CODE",
  0x2a: "SOURCE_VERSION",
  0x2c: "ENCRYPTION_INFO_64",
  0x2f: "LINKER_OPTIMIZATION_HINT",
  0x32: "BUILD_VERSION",
  0x80000018: "LOAD_WEAK_DYLIB",
  0x8000001c: "RPATH",
  0x8000001f: "REEXPORT_DYLIB",
  0x80000022: "DYLD_INFO_ONLY",
  0x80000023: "LOAD_UPWARD_DYLIB",
  0x80000028: "MAIN",
  0x80000033: "DYLD_EXPORTS_TRIE",
  0x80000034: "DYLD_CHAINED_FIXUPS",
};

const PLATFORMS: Record<number, string> = { 1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "Mac Catalyst", 7: "iOS simulator", 8: "tvOS simulator", 9: "watchOS simulator", 10: "DriverKit", 11: "visionOS", 12: "visionOS simulator" };

const CS_FLAGS: [number, string][] = [
  [0x2, "adhoc"],
  [0x100, "hard"],
  [0x200, "kill"],
  [0x800, "restrict"],
  [0x1000, "enforcement"],
  [0x2000, "library-validation"],
  [0x10000, "runtime"],
  [0x20000, "linker-signed"],
];

/** Entitlements that weaken the hardened runtime or grant sensitive access. */
export const NOTABLE_ENTITLEMENTS: Record<string, string> = {
  "com.apple.security.cs.disable-library-validation": "Loads libraries not signed by Apple or the same team",
  "com.apple.security.cs.allow-dyld-environment-variables": "Honours DYLD_* variables (library injection)",
  "com.apple.security.cs.allow-unsigned-executable-memory": "Allows writable-executable memory",
  "com.apple.security.cs.allow-jit": "Allows JIT memory",
  "com.apple.security.cs.disable-executable-page-protection": "Disables executable page protection",
  "com.apple.security.get-task-allow": "Other processes may attach and debug (development builds)",
  "com.apple.security.cs.debugger": "Acts as a debugger",
  "com.apple.security.automation.apple-events": "Sends Apple Events to other apps",
  "com.apple.security.device.camera": "Camera access",
  "com.apple.security.device.audio-input": "Microphone access",
  "com.apple.developer.endpoint-security.client": "Endpoint Security client",
  "com.apple.private.tcc.allow": "Private TCC bypass entitlement",
};

export interface MachoSegment {
  name: string;
  vmaddr: string;
  vmsize: number;
  fileoff: number;
  filesize: number;
  maxprot: string;
  initprot: string;
  sections: { name: string; segment: string; addr: string; size: number; offset: number; entropy: number | null }[];
}

export interface MachoSignature {
  offset: number;
  size: number;
  identifier?: string;
  teamId?: string;
  flags: string[];
  hashType?: string;
  adhoc: boolean;
  hasCms: boolean;
  certificates: Certificate[];
  entitlements?: string;
  notableEntitlements: { key: string; note: string }[];
  error?: string;
}

export interface MachoSlice {
  cpu: string;
  is64: boolean;
  fileType: string;
  flags: string[];
  commands: { cmd: string; size: number }[];
  segments: MachoSegment[];
  libraries: { name: string; kind: string; currentVersion: string }[];
  rpaths: string[];
  dylinker?: string;
  uuid?: string;
  entryOffset?: number;
  platform?: string;
  minOs?: string;
  sdk?: string;
  encrypted: boolean;
  imports: string[];
  exports: string[];
  symbolsTruncated: boolean;
  signature?: MachoSignature;
  anomalies: string[];
}

export interface MachoAnalysis {
  fat: boolean;
  slices: (MachoSlice & { offset: number; size: number })[];
}

const ver = (v: number) => `${v >>> 16}.${(v >>> 8) & 0xff}.${v & 0xff}`;
const prot = (p: number) => `${p & 1 ? "r" : "-"}${p & 2 ? "w" : "-"}${p & 4 ? "x" : "-"}`;

export function parseMacho(bytes: Uint8Array): MachoAnalysis {
  if (bytes.length < 8) throw new ParseError("File is too small for Mach-O");
  const be = new Reader(bytes, false);
  const magic = be.u32(0);
  if (magic === 0xcafebabe || magic === 0xcafebabf) {
    const wide = magic === 0xcafebabf;
    const n = be.u32(4);
    if (n === 0 || n > 32) throw new ParseError(`Universal header declares ${n} architectures`);
    const slices: MachoAnalysis["slices"] = [];
    for (let i = 0; i < n; i++) {
      const o = 8 + i * (wide ? 32 : 20);
      if (!be.has(o, wide ? 32 : 20)) break;
      const offset = wide ? be.u64n(o + 8) : be.u32(o + 8);
      const size = wide ? be.u64n(o + 16) : be.u32(o + 12);
      if (!be.has(offset, Math.min(size, 32))) continue;
      const slice = bytes.subarray(offset, Math.min(bytes.length, offset + size));
      try {
        slices.push({ ...parseThin(slice), offset, size });
      } catch (err) {
        slices.push({ ...emptySlice(err), offset, size });
      }
    }
    return { fat: true, slices };
  }
  return { fat: false, slices: [{ ...parseThin(bytes), offset: 0, size: bytes.length }] };
}

function emptySlice(err: unknown): MachoSlice {
  return { cpu: "?", is64: false, fileType: "?", flags: [], commands: [], segments: [], libraries: [], rpaths: [], encrypted: false, imports: [], exports: [], symbolsTruncated: false, anomalies: [err instanceof Error ? err.message : String(err)] };
}

function parseThin(bytes: Uint8Array): MachoSlice {
  const le = new Reader(bytes, true).u32(0);
  let littleEndian: boolean;
  let is64: boolean;
  if (le === 0xfeedface || le === 0xfeedfacf) {
    littleEndian = true;
    is64 = le === 0xfeedfacf;
  } else if (le === 0xcefaedfe || le === 0xcffaedfe) {
    littleEndian = false;
    is64 = le === 0xcffaedfe;
  } else throw new ParseError("No Mach-O magic");
  const r = new Reader(bytes, littleEndian);
  const cputype = r.u32(4);
  const filetype = r.u32(12);
  const ncmds = r.u32(16);
  const flagsValue = r.u32(24);
  const anomalies: string[] = [];
  const commands: MachoSlice["commands"] = [];
  const segments: MachoSegment[] = [];
  const libraries: MachoSlice["libraries"] = [];
  const rpaths: string[] = [];
  let dylinker: string | undefined;
  let uuid: string | undefined;
  let entryOffset: number | undefined;
  let platform: string | undefined;
  let minOs: string | undefined;
  let sdk: string | undefined;
  let encrypted = false;
  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | undefined;
  let codeSig: { off: number; size: number } | undefined;

  let o = is64 ? 32 : 28;
  if (ncmds > MAX_COMMANDS) anomalies.push(`${ncmds} load commands declared; only ${MAX_COMMANDS} are read`);
  for (let i = 0; i < Math.min(ncmds, MAX_COMMANDS); i++) {
    if (!r.has(o, 8)) {
      anomalies.push("Load commands run past the end of the file");
      break;
    }
    const cmd = r.u32(o);
    const size = r.u32(o + 4);
    if (size < 8 || !r.has(o, size)) {
      anomalies.push(`Load command ${i} has an invalid size (${size})`);
      break;
    }
    commands.push({ cmd: LC[cmd] ?? `0x${cmd.toString(16)}`, size });
    const lcStr = (fieldOff: number) => {
      const s = r.u32(o + fieldOff);
      return s < size ? r.cstring(o + s, size - s) : "";
    };
    switch (cmd) {
      case 0x1:
      case 0x19: {
        const w = cmd === 0x19;
        const name = latin1(r.slice(o + 8, 16)).replace(/\0+$/, "");
        const vmaddr = w ? r.u64(o + 24) : BigInt(r.u32(o + 24));
        const vmsize = w ? r.u64n(o + 32) : r.u32(o + 28);
        const fileoff = w ? r.u64n(o + 40) : r.u32(o + 32);
        const filesize = w ? r.u64n(o + 48) : r.u32(o + 36);
        const maxprot = r.u32(o + (w ? 56 : 40));
        const initprot = r.u32(o + (w ? 60 : 44));
        const nsects = r.u32(o + (w ? 64 : 48));
        const seg: MachoSegment = { name, vmaddr: `0x${vmaddr.toString(16)}`, vmsize, fileoff, filesize, maxprot: prot(maxprot), initprot: prot(initprot), sections: [] };
        const secBase = o + (w ? 72 : 56);
        const secSize = w ? 80 : 68;
        for (let s = 0; s < Math.min(nsects, 256); s++) {
          const so = secBase + s * secSize;
          if (!r.has(so, secSize) || so + secSize > o + size) break;
          const sname = latin1(r.slice(so, 16)).replace(/\0+$/, "");
          const addr = w ? r.u64(so + 32) : BigInt(r.u32(so + 32));
          const ssize = w ? r.u64n(so + 40) : r.u32(so + 36);
          const soff = r.u32(so + (w ? 48 : 40));
          const zerofill = (r.u32(so + (w ? 64 : 56)) & 0xff) === 1;
          seg.sections.push({
            name: sname,
            segment: latin1(r.slice(so + 16, 16)).replace(/\0+$/, ""),
            addr: `0x${addr.toString(16)}`,
            size: ssize,
            offset: soff,
            entropy: !zerofill && soff && ssize && soff < r.length ? entropy(bytes, soff, Math.min(r.length, soff + ssize)) : null,
          });
        }
        if ((initprot & 6) === 6) anomalies.push(`Segment ${name} is mapped writable and executable`);
        segments.push(seg);
        break;
      }
      case 0xc:
      case 0x80000018:
      case 0x8000001f:
      case 0x20:
      case 0x80000023:
        libraries.push({ name: lcStr(8), kind: LC[cmd], currentVersion: ver(r.u32(o + 16)) });
        break;
      case 0xe:
        dylinker = lcStr(8);
        break;
      case 0x8000001c:
        rpaths.push(lcStr(8));
        break;
      case 0x1b: {
        const u = hex(r.slice(o + 8, 16)).toUpperCase();
        uuid = `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20)}`;
        break;
      }
      case 0x80000028:
        entryOffset = r.u64n(o + 8);
        break;
      case 0x21:
      case 0x2c:
        if (r.u32(o + 16) !== 0) encrypted = true;
        break;
      case 0x24:
      case 0x25:
        platform = cmd === 0x24 ? "macOS" : "iOS";
        minOs = ver(r.u32(o + 8));
        sdk = ver(r.u32(o + 12));
        break;
      case 0x32:
        platform = PLATFORMS[r.u32(o + 8)] ?? `platform ${r.u32(o + 8)}`;
        minOs = ver(r.u32(o + 12));
        sdk = ver(r.u32(o + 16));
        break;
      case 0x2:
        symtab = { symoff: r.u32(o + 8), nsyms: r.u32(o + 12), stroff: r.u32(o + 16), strsize: r.u32(o + 20) };
        break;
      case 0x1d:
        codeSig = { off: r.u32(o + 8), size: r.u32(o + 12) };
        break;
    }
    o += size;
  }

  // Symbols: undefined externals are imports, defined externals are exports.
  const imports: string[] = [];
  const exports: string[] = [];
  let symbolsTruncated = false;
  if (symtab) {
    const entSize = is64 ? 16 : 12;
    const n = Math.min(symtab.nsyms, MAX_SYMBOLS);
    if (symtab.nsyms > MAX_SYMBOLS) symbolsTruncated = true;
    for (let i = 0; i < n; i++) {
      const so = symtab.symoff + i * entSize;
      if (!r.has(so, entSize)) break;
      const strx = r.u32(so);
      const type = r.u8(so + 4);
      if (type & 0xe0) continue; // stab debugging entry
      const ext = (type & 0x01) !== 0;
      const kind = type & 0x0e;
      if (!ext || strx >= symtab.strsize) continue;
      const name = r.cstring(symtab.stroff + strx, 256);
      if (!name) continue;
      if (kind === 0) imports.push(name);
      else if (kind === 0x0e) exports.push(name);
    }
  }

  let signature: MachoSignature | undefined;
  if (codeSig) signature = parseCodeSignature(bytes, codeSig.off, codeSig.size);

  return {
    cpu: CPU[cputype] ?? `cpu 0x${cputype.toString(16)}`,
    is64,
    fileType: FILETYPES[filetype] ?? `type ${filetype}`,
    flags: HEADER_FLAGS.filter(([bit]) => (flagsValue & bit) !== 0).map(([, n]) => n),
    commands,
    segments,
    libraries,
    rpaths,
    dylinker,
    uuid,
    entryOffset,
    platform,
    minOs,
    sdk,
    encrypted,
    imports,
    exports,
    symbolsTruncated,
    signature,
    anomalies,
  };
}

const HASH_TYPES: Record<number, string> = { 1: "SHA-1", 2: "SHA-256", 3: "SHA-256 (truncated)", 4: "SHA-384" };

function parseCodeSignature(bytes: Uint8Array, off: number, size: number): MachoSignature {
  const sig: MachoSignature = { offset: off, size, flags: [], adhoc: false, hasCms: false, certificates: [], notableEntitlements: [] };
  try {
    const r = new Reader(bytes, false); // code signature structures are big-endian
    if (!r.has(off, 12) || r.u32(off) !== 0xfade0cc0) throw new ParseError("Code signature superblob magic not found");
    const count = Math.min(r.u32(off + 8), 64);
    for (let i = 0; i < count; i++) {
      const idx = off + 12 + i * 8;
      if (!r.has(idx, 8)) break;
      const blobOff = off + r.u32(idx + 4);
      if (!r.has(blobOff, 8)) continue;
      const magic = r.u32(blobOff);
      const length = r.u32(blobOff + 4);
      if (!r.has(blobOff, length)) continue;
      if (magic === 0xfade0c02 && !sig.identifier) {
        const version = r.u32(blobOff + 8);
        const flags = r.u32(blobOff + 12);
        sig.flags = CS_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(([, n]) => n);
        sig.adhoc = (flags & 0x2) !== 0;
        sig.identifier = r.cstring(blobOff + r.u32(blobOff + 20), 256);
        sig.hashType = HASH_TYPES[r.u8(blobOff + 37)] ?? `type ${r.u8(blobOff + 37)}`;
        if (version >= 0x20200 && length >= 52) {
          const team = r.u32(blobOff + 48);
          if (team) sig.teamId = r.cstring(blobOff + team, 64);
        }
      } else if (magic === 0xfade7171) {
        sig.entitlements = new TextDecoder("utf-8", { fatal: false }).decode(r.slice(blobOff + 8, Math.min(length - 8, 256 * 1024)));
        for (const [key, note] of Object.entries(NOTABLE_ENTITLEMENTS)) {
          const re = new RegExp(`<key>${key.replace(/\./g, "\\.")}</key>\\s*<true\\s*/>`);
          if (re.test(sig.entitlements)) sig.notableEntitlements.push({ key, note });
        }
      } else if (magic === 0xfade0b01 && length > 8) {
        sig.hasCms = true;
        const cms = r.slice(blobOff + 8, length - 8);
        try {
          const ci = parseDer(cms);
          const signedData = ci.children?.[1]?.children?.[0];
          const certSet = signedData?.children?.find((c) => c.cls === "context" && c.tag === 0);
          for (const c of certSet?.children ?? []) {
            try {
              sig.certificates.push(parseCertificate(cms, c));
            } catch {
              // skip
            }
          }
        } catch {
          // The CMS blob is optional detail; its absence is reported by hasCms/certificates.
        }
      }
    }
  } catch (err) {
    sig.error = err instanceof Error ? err.message : String(err);
  }
  return sig;
}
