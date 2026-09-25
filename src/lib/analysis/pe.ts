import { ParseError, Reader, entropy, hex, latin1 } from "./bytes";
import { md5 } from "./hash";
import { identify, type FileType } from "./magic";
import { integerHex, oid, oidName, parseCertificate, parseDer, text, time, type Asn1, type Certificate } from "./der";

// Portable Executable (PE/COFF) static parser. Reads structure only; nothing
// is mapped, relocated or executed. Every table walk is bounded.

const MAX_SECTIONS = 96;
const MAX_IMPORT_DLLS = 512;
const MAX_IMPORTS_PER_DLL = 4096;
const MAX_EXPORTS = 16_384;
const MAX_RESOURCES = 4096;

export const MACHINES: Record<number, string> = {
  0x0: "Unknown",
  0x14c: "x86 (i386)",
  0x8664: "x86-64 (AMD64)",
  0x1c0: "ARM",
  0x1c4: "ARM Thumb-2 (ARMNT)",
  0xaa64: "ARM64",
  0xa641: "ARM64EC",
  0xa64e: "ARM64X",
  0x200: "Itanium (IA-64)",
  0xebc: "EFI byte code",
  0x5032: "RISC-V 32",
  0x5064: "RISC-V 64",
};

export const SUBSYSTEMS: Record<number, string> = {
  1: "Native (driver / kernel)",
  2: "Windows GUI",
  3: "Windows console",
  5: "OS/2 console",
  7: "POSIX console",
  9: "Windows CE GUI",
  10: "EFI application",
  11: "EFI boot service driver",
  12: "EFI runtime driver",
  13: "EFI ROM",
  14: "Xbox",
  16: "Windows boot application",
};

const FILE_FLAGS: [number, string][] = [
  [0x0001, "RELOCS_STRIPPED"],
  [0x0002, "EXECUTABLE_IMAGE"],
  [0x0020, "LARGE_ADDRESS_AWARE"],
  [0x0100, "32BIT_MACHINE"],
  [0x0200, "DEBUG_STRIPPED"],
  [0x0400, "REMOVABLE_RUN_FROM_SWAP"],
  [0x0800, "NET_RUN_FROM_SWAP"],
  [0x1000, "SYSTEM"],
  [0x2000, "DLL"],
  [0x4000, "UP_SYSTEM_ONLY"],
];

const DLL_FLAGS: [number, string][] = [
  [0x0020, "HIGH_ENTROPY_VA"],
  [0x0040, "DYNAMIC_BASE"],
  [0x0080, "FORCE_INTEGRITY"],
  [0x0100, "NX_COMPAT"],
  [0x0200, "NO_ISOLATION"],
  [0x0400, "NO_SEH"],
  [0x0800, "NO_BIND"],
  [0x1000, "APPCONTAINER"],
  [0x2000, "WDM_DRIVER"],
  [0x4000, "GUARD_CF"],
  [0x8000, "TERMINAL_SERVER_AWARE"],
];

const SECTION_FLAGS: [number, string][] = [
  [0x00000020, "CODE"],
  [0x00000040, "INITIALIZED_DATA"],
  [0x00000080, "UNINITIALIZED_DATA"],
  [0x02000000, "DISCARDABLE"],
  [0x04000000, "NOT_CACHED"],
  [0x08000000, "NOT_PAGED"],
  [0x10000000, "SHARED"],
  [0x20000000, "EXECUTE"],
  [0x40000000, "READ"],
  [0x80000000, "WRITE"],
];

export const DIRECTORY_NAMES = ["Export", "Import", "Resource", "Exception", "Security (certificates)", "Base relocation", "Debug", "Architecture", "Global pointer", "TLS", "Load config", "Bound import", "IAT", "Delay import", "CLR runtime (.NET)", "Reserved"];

export const RESOURCE_TYPES: Record<number, string> = {
  1: "CURSOR",
  2: "BITMAP",
  3: "ICON",
  4: "MENU",
  5: "DIALOG",
  6: "STRING",
  7: "FONTDIR",
  8: "FONT",
  9: "ACCELERATOR",
  10: "RCDATA",
  11: "MESSAGETABLE",
  12: "GROUP_CURSOR",
  14: "GROUP_ICON",
  16: "VERSION",
  17: "DLGINCLUDE",
  19: "PLUGPLAY",
  20: "VXD",
  21: "ANICURSOR",
  22: "ANIICON",
  23: "HTML",
  24: "MANIFEST",
};

const DEBUG_TYPES: Record<number, string> = {
  1: "COFF",
  2: "CodeView",
  3: "FPO",
  4: "Misc",
  5: "Exception",
  6: "Fixup",
  9: "Borland",
  12: "VC_FEATURE",
  13: "POGO",
  14: "ILTCG",
  16: "Reproducible build",
  17: "Embedded portable PDB",
  19: "PDB checksum",
  20: "Extended DLL characteristics",
};

/** Section names written by known packers and protectors. */
export const PACKER_SECTIONS: Record<string, string> = {
  UPX0: "UPX",
  UPX1: "UPX",
  UPX2: "UPX",
  "UPX!": "UPX",
  ".aspack": "ASPack",
  ".adata": "ASPack",
  ".ASPack": "ASPack",
  ".MPRESS1": "MPRESS",
  ".MPRESS2": "MPRESS",
  ".themida": "Themida",
  ".winlice": "WinLicense",
  ".vmp0": "VMProtect",
  ".vmp1": "VMProtect",
  ".vmp2": "VMProtect",
  ".enigma1": "Enigma Protector",
  ".enigma2": "Enigma Protector",
  ".petite": "Petite",
  ".nsp0": "NsPack",
  ".nsp1": "NsPack",
  ".nsp2": "NsPack",
  pec1: "PECompact",
  pec2: "PECompact",
  PEC2: "PECompact",
  PEC2TO: "PECompact",
  ".RLPack": "RLPack",
  ".yP": "Y0da Protector",
  ".y0da": "Y0da Protector",
  ".perplex": "Perplex",
  ".packed": "Unknown packer",
  ".spack": "Simple Pack",
  ".svkp": "SVKP",
  ".taz": "PESpin",
  BitArts: "Crunch",
  ".ccg": "CCG",
  ".charmve": "Pin (instrumentation)",
  ".boom": "Boomerang",
  ".ecode": "EPL",
  ".edata2": "EPL",
  "kkrunchy": "kkrunchy",
  ".mackt": "ImpRec (rebuilt imports)",
  ".MaskPE": "MaskPE",
  ".neolit": "NeoLite",
  ".neolite": "NeoLite",
  ".sforce3": "StarForce",
  ".shrink1": "Shrinker",
  ".shrink2": "Shrinker",
  ".Upack": "Upack",
  ".ByDwing": "Upack",
  ".WWPACK": "WWPack",
  ".WWP32": "WWPack",
  ".rmnet": "Ramnit infection marker",
  ".stab": "PELock",
  ".gentee": "Gentee installer",
  ".imrsiv": "",
};

export interface PeSection {
  index: number;
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawOffset: number;
  rawSize: number;
  characteristics: number;
  flags: string[];
  entropy: number;
  md5: string;
  readable: boolean;
  writable: boolean;
  executable: boolean;
  packer?: string;
}

export interface PeImportFunction {
  name?: string;
  ordinal?: number;
  hint?: number;
}

export interface PeImport {
  dll: string;
  delayed: boolean;
  functions: PeImportFunction[];
}

export interface PeExport {
  ordinal: number;
  name?: string;
  rva: number;
  forwarder?: string;
}

export interface PeResource {
  type: string;
  typeId?: number;
  name: string;
  language: number;
  rva: number;
  offset: number | null;
  size: number;
  entropy: number | null;
  detected?: FileType;
}

export interface RichEntry {
  productId: number;
  build: number;
  count: number;
}

export interface PeSignature {
  present: boolean;
  offset: number;
  size: number;
  revision?: number;
  certificateType?: number;
  parsed: boolean;
  error?: string;
  digestAlgorithm?: string;
  signedDigest?: string;
  programName?: string;
  moreInfoUrl?: string;
  signingTime?: string | null;
  signer?: Certificate;
  certificates: Certificate[];
  nestedSignatures: number;
  /** Computed Authenticode image hash (when the algorithm is supported). */
  imageDigest?: string;
  /** imageDigest === signedDigest. Proves the file matches what was signed; says nothing about who signed it. */
  digestMatches?: boolean;
}

export interface PeAnalysis {
  format: "PE32" | "PE32+";
  machine: number;
  machineName: string;
  is64: boolean;
  isDll: boolean;
  isDriver: boolean;
  isDotNet: boolean;
  timestamp: number;
  timestampIso: string | null;
  reproducible: boolean;
  characteristics: string[];
  dllCharacteristics: string[];
  subsystem: string;
  entryPoint: number;
  entrySection: string | null;
  imageBase: string;
  sizeOfImage: number;
  sizeOfHeaders: number;
  linkerVersion: string;
  osVersion: string;
  checksum: { stored: number; computed: number };
  eLfanew: number;
  headerOffsets: { dos: number; pe: number; optional: number; sectionTable: number };
  directories: { index: number; name: string; rva: number; size: number }[];
  sections: PeSection[];
  imports: PeImport[];
  exports: { dllName?: string; timestamp?: number; entries: PeExport[] };
  resources: PeResource[];
  version: Record<string, string>;
  manifest?: { executionLevel?: string; uiAccess?: boolean; raw: string };
  debug: { type: string; timestamp: number; pdb?: string; guid?: string; age?: number }[];
  tlsCallbacks: { va: string; rva: number; section: string | null }[];
  loadConfig?: { securityCookie: boolean; cfgInstrumented: boolean; sehTable: boolean };
  rich?: { entries: RichEntry[]; key: string; checksumValid: boolean; hash: string; offset: number; size: number };
  signature: PeSignature;
  overlay?: { offset: number; size: number; entropy: number; detected: FileType };
  imphash?: string;
  imphashExact: boolean;
  importCount: number;
  anomalies: string[];
}

function flagsOf(value: number, table: [number, string][]): string[] {
  return table.filter(([bit]) => (value & bit) !== 0).map(([, name]) => name);
}

function rol32(value: number, bits: number): number {
  bits &= 31;
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

export function parsePe(bytes: Uint8Array): PeAnalysis {
  const r = new Reader(bytes, true);
  const anomalies: string[] = [];
  if (r.length < 64 || r.u16(0) !== 0x5a4d) throw new ParseError("No MZ header");
  const eLfanew = r.u32(0x3c);
  if (eLfanew < 0x40 || eLfanew > Math.min(r.length - 24, 0x10000000)) throw new ParseError(`e_lfanew (0x${eLfanew.toString(16)}) does not point inside the file: this is an MZ (DOS) file without a PE header`);
  if (r.u32(eLfanew) !== 0x00004550) throw new ParseError("PE signature not found at e_lfanew: DOS executable or damaged PE");

  const coff = eLfanew + 4;
  const machine = r.u16(coff);
  const numberOfSections = r.u16(coff + 2);
  const timestamp = r.u32(coff + 4);
  const sizeOfOptionalHeader = r.u16(coff + 16);
  const characteristicsValue = r.u16(coff + 18);
  const opt = coff + 20;
  const magic = r.u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) throw new ParseError(`Unknown optional header magic 0x${magic.toString(16)}`);
  const is64 = magic === 0x20b;

  const linkerVersion = `${r.u8(opt + 2)}.${r.u8(opt + 3)}`;
  const entryPoint = r.u32(opt + 16);
  const imageBase = is64 ? r.u64(opt + 24) : BigInt(r.u32(opt + 28));
  const sectionAlignment = r.u32(opt + 32);
  const fileAlignment = r.u32(opt + 36);
  const osVersion = `${r.u16(opt + 40)}.${r.u16(opt + 42)}`;
  const sizeOfImage = r.u32(opt + 56);
  const sizeOfHeaders = r.u32(opt + 60);
  const checksumOffset = opt + 64;
  const storedChecksum = r.u32(checksumOffset);
  const subsystemValue = r.u16(opt + 68);
  const dllCharacteristicsValue = r.u16(opt + 70);
  const rvaCountOffset = is64 ? opt + 108 : opt + 92;
  const dirOffset = rvaCountOffset + 4;
  const numberOfRva = Math.min(16, r.u32(rvaCountOffset));
  if (r.u32(rvaCountOffset) > 16) anomalies.push(`NumberOfRvaAndSizes is ${r.u32(rvaCountOffset)} (more than 16)`);

  const directories: PeAnalysis["directories"] = [];
  for (let i = 0; i < numberOfRva; i++) {
    const o = dirOffset + i * 8;
    if (!r.has(o, 8)) break;
    directories.push({ index: i, name: DIRECTORY_NAMES[i], rva: r.u32(o), size: r.u32(o + 4) });
  }
  const dir = (i: number) => directories[i] && directories[i].rva && directories[i].size ? directories[i] : undefined;

  if (fileAlignment && (fileAlignment & (fileAlignment - 1)) !== 0) anomalies.push(`FileAlignment 0x${fileAlignment.toString(16)} is not a power of two`);
  if (sectionAlignment && sectionAlignment < fileAlignment) anomalies.push("SectionAlignment is smaller than FileAlignment");

  // Sections
  const sectionTable = opt + sizeOfOptionalHeader;
  if (numberOfSections > MAX_SECTIONS) anomalies.push(`${numberOfSections} sections declared; only the first ${MAX_SECTIONS} are read`);
  const sections: PeSection[] = [];
  for (let i = 0; i < Math.min(numberOfSections, MAX_SECTIONS); i++) {
    const o = sectionTable + i * 40;
    if (!r.has(o, 40)) {
      anomalies.push(`Section table is truncated after ${i} of ${numberOfSections} entries`);
      break;
    }
    let name = latin1(r.slice(o, 8)).replace(/\0+$/, "");
    if (name.startsWith("/")) name = `${name} (COFF string table)`;
    const virtualSize = r.u32(o + 8);
    const virtualAddress = r.u32(o + 12);
    const rawSize = r.u32(o + 16);
    const rawOffset = r.u32(o + 20);
    const characteristics = r.u32(o + 36);
    const available = rawOffset < r.length ? Math.min(rawSize, r.length - rawOffset) : 0;
    if (rawSize && available < rawSize) anomalies.push(`Section ${name || `#${i}`} raw data extends past the end of the file`);
    const data = available ? bytes.subarray(rawOffset, rawOffset + available) : new Uint8Array(0);
    const trimmed = name.replace(/\0/g, "");
    sections.push({
      index: i,
      name,
      virtualAddress,
      virtualSize,
      rawOffset,
      rawSize,
      characteristics,
      flags: flagsOf(characteristics, SECTION_FLAGS),
      entropy: entropy(data),
      md5: md5(data),
      readable: (characteristics & 0x40000000) !== 0,
      writable: (characteristics & 0x80000000) !== 0,
      executable: (characteristics & 0x20000000) !== 0 || (characteristics & 0x20) !== 0,
      packer: PACKER_SECTIONS[trimmed] || undefined,
    });
  }

  const sectionFor = (rva: number) => sections.find((s) => rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize));
  const rvaToOffset = (rva: number): number | null => {
    if (!Number.isFinite(rva) || rva < 0) return null;
    if (rva < sizeOfHeaders && rva < r.length) return rva;
    const s = sectionFor(rva);
    if (!s) return null;
    const delta = rva - s.virtualAddress;
    if (delta >= s.rawSize) return null; // lives in the zero-filled tail
    const off = s.rawOffset + delta;
    return off < r.length ? off : null;
  };
  const strAt = (rva: number, max = 256) => {
    const off = rvaToOffset(rva);
    return off === null ? "" : r.cstring(off, max);
  };
  const ptrSize = is64 ? 8 : 4;
  const readPtr = (off: number): bigint => (is64 ? r.u64(off) : BigInt(r.u32(off)));

  // Imports
  const imports: PeImport[] = [];
  const readThunks = (thunkRva: number): PeImportFunction[] => {
    const fns: PeImportFunction[] = [];
    const start = rvaToOffset(thunkRva);
    if (start === null) return fns;
    const ordinalFlag = is64 ? BigInt("0x8000000000000000") : BigInt(0x80000000);
    for (let n = 0; n < MAX_IMPORTS_PER_DLL && r.has(start + n * ptrSize, ptrSize); n++) {
      const v = readPtr(start + n * ptrSize);
      if (v === BigInt(0)) break;
      if (v & ordinalFlag) fns.push({ ordinal: Number(v & BigInt(0xffff)) });
      else {
        const hintOff = rvaToOffset(Number(v & BigInt(0x7fffffff)));
        if (hintOff === null || !r.has(hintOff, 2)) {
          fns.push({ name: "<invalid thunk>" });
          continue;
        }
        fns.push({ hint: r.u16(hintOff), name: r.cstring(hintOff + 2, 512) });
      }
    }
    return fns;
  };

  const importDir = dir(1);
  if (importDir) {
    const start = rvaToOffset(importDir.rva);
    if (start === null) anomalies.push("Import directory points outside the mapped sections");
    for (let i = 0; start !== null && i < MAX_IMPORT_DLLS && r.has(start + i * 20, 20); i++) {
      const off = start + i * 20;
      const ilt = r.u32(off);
      const nameRva = r.u32(off + 12);
      const iat = r.u32(off + 16);
      if (!ilt && !nameRva && !iat) break;
      const dll = strAt(nameRva) || "<unnamed>";
      imports.push({ dll, delayed: false, functions: readThunks(ilt || iat) });
    }
  }
  const delayDir = dir(13);
  if (delayDir) {
    const start = rvaToOffset(delayDir.rva);
    for (let i = 0; start !== null && i < MAX_IMPORT_DLLS && r.has(start + i * 32, 32); i++) {
      const off = start + i * 32;
      const attributes = r.u32(off);
      const nameRva = r.u32(off + 4);
      const intRva = r.u32(off + 16);
      if (!nameRva && !intRva) break;
      // Old-style delay descriptors hold VAs instead of RVAs.
      const fix = (v: number) => ((attributes & 1) === 0 && v ? Number(BigInt(v) - imageBase) : v);
      imports.push({ dll: strAt(fix(nameRva)) || "<unnamed>", delayed: true, functions: readThunks(fix(intRva)) });
    }
  }
  const importCount = imports.reduce((n, i) => n + i.functions.length, 0);

  // imphash (pefile-compatible for non-ordinal imports; ordinal imports from
  // ws2_32/wsock32/oleaut32 need pefile's name tables, so we flag those).
  let imphashExact = true;
  const impParts: string[] = [];
  for (const imp of imports.filter((i) => !i.delayed)) {
    let lib = imp.dll.toLowerCase();
    const dot = lib.lastIndexOf(".");
    if (dot > 0 && ["ocx", "sys", "dll"].includes(lib.slice(dot + 1))) lib = lib.slice(0, dot);
    for (const fn of imp.functions) {
      if (fn.name) impParts.push(`${lib}.${fn.name.toLowerCase()}`);
      else if (fn.ordinal !== undefined) {
        if (["ws2_32", "wsock32", "oleaut32"].includes(lib)) imphashExact = false;
        impParts.push(`${lib}.ord${fn.ordinal}`);
      }
    }
  }
  const imphash = impParts.length ? md5(new TextEncoder().encode(impParts.join(","))) : undefined;

  // Exports
  const exports: PeAnalysis["exports"] = { entries: [] };
  const exportDir = dir(0);
  if (exportDir) {
    const off = rvaToOffset(exportDir.rva);
    if (off !== null && r.has(off, 40)) {
      exports.timestamp = r.u32(off + 4);
      exports.dllName = strAt(r.u32(off + 12)) || undefined;
      const base = r.u32(off + 16);
      const nFunctions = Math.min(r.u32(off + 20), MAX_EXPORTS);
      const nNames = Math.min(r.u32(off + 24), MAX_EXPORTS);
      const fnOff = rvaToOffset(r.u32(off + 28));
      const namesOff = rvaToOffset(r.u32(off + 32));
      const ordsOff = rvaToOffset(r.u32(off + 36));
      const names = new Map<number, string>();
      if (namesOff !== null && ordsOff !== null) {
        for (let i = 0; i < nNames && r.has(namesOff + i * 4, 4) && r.has(ordsOff + i * 2, 2); i++) names.set(r.u16(ordsOff + i * 2), strAt(r.u32(namesOff + i * 4)));
      }
      if (fnOff !== null) {
        for (let i = 0; i < nFunctions && r.has(fnOff + i * 4, 4); i++) {
          const rva = r.u32(fnOff + i * 4);
          if (!rva) continue;
          const forwarded = rva >= exportDir.rva && rva < exportDir.rva + exportDir.size;
          exports.entries.push({ ordinal: base + i, name: names.get(i), rva, forwarder: forwarded ? strAt(rva) : undefined });
        }
      }
    }
  }

  // Resources
  const resources: PeResource[] = [];
  const version: Record<string, string> = {};
  let manifest: PeAnalysis["manifest"];
  const resDir = dir(2);
  if (resDir) {
    const base = rvaToOffset(resDir.rva);
    if (base !== null) {
      const visited = new Set<number>();
      const nameOf = (entryName: number, isType: boolean): { label: string; id?: number } => {
        if (entryName & 0x80000000) {
          const o = base + (entryName & 0x7fffffff);
          if (!r.has(o, 2)) return { label: "<bad name>" };
          return { label: r.utf16(o + 2, Math.min(r.u16(o), 256)) };
        }
        return { label: isType ? (RESOURCE_TYPES[entryName] ?? String(entryName)) : String(entryName), id: entryName };
      };
      const walk = (dirOff: number, depth: number, path: { label: string; id?: number }[]) => {
        if (depth > 2 || visited.has(dirOff) || !r.has(dirOff, 16) || resources.length >= MAX_RESOURCES) return;
        visited.add(dirOff);
        const count = Math.min(r.u16(dirOff + 12) + r.u16(dirOff + 14), 1024);
        for (let i = 0; i < count && resources.length < MAX_RESOURCES; i++) {
          const e = dirOff + 16 + i * 8;
          if (!r.has(e, 8)) break;
          const entryName = r.u32(e);
          const target = r.u32(e + 4);
          const here = [...path, nameOf(entryName, depth === 0)];
          if (target & 0x80000000) walk(base + (target & 0x7fffffff), depth + 1, here);
          else {
            const d = base + target;
            if (!r.has(d, 16)) continue;
            const rva = r.u32(d);
            const size = r.u32(d + 4);
            const offset = rvaToOffset(rva);
            const available = offset !== null ? Math.min(size, r.length - offset) : 0;
            const data = offset !== null && available > 0 ? bytes.subarray(offset, offset + available) : null;
            const typeInfo = here[0];
            const res: PeResource = {
              type: typeInfo.label,
              typeId: typeInfo.id,
              name: here[1]?.label ?? "",
              language: here[2]?.id ?? 0,
              rva,
              offset,
              size,
              entropy: data ? entropy(data) : null,
            };
            if (data && data.length >= 4) {
              const detected = identify(data);
              if (detected.id !== "data" && detected.id !== "text") res.detected = detected;
            }
            resources.push(res);
            if (data && typeInfo.id === 16 && !Object.keys(version).length) Object.assign(version, parseVersionInfo(data));
            if (data && typeInfo.id === 24 && !manifest) manifest = parseManifest(data);
          }
        }
      };
      walk(base, 0, []);
    }
  }

  // Debug directory
  const debug: PeAnalysis["debug"] = [];
  let reproducible = false;
  const debugDir = dir(6);
  if (debugDir) {
    const off = rvaToOffset(debugDir.rva);
    const count = Math.min(Math.floor(debugDir.size / 28), 32);
    for (let i = 0; off !== null && i < count && r.has(off + i * 28, 28); i++) {
      const e = off + i * 28;
      const type = r.u32(e + 12);
      const size = r.u32(e + 16);
      const ptr = r.u32(e + 24);
      const entry: PeAnalysis["debug"][number] = { type: DEBUG_TYPES[type] ?? `Type ${type}`, timestamp: r.u32(e + 4) };
      if (type === 16) reproducible = true;
      if (type === 2 && ptr && r.has(ptr, 24) && size >= 24) {
        if (r.u32(ptr) === 0x53445352) {
          // RSDS
          const g = r.slice(ptr + 4, 16);
          const d1 = r.u32(ptr + 4).toString(16).padStart(8, "0");
          const d2 = r.u16(ptr + 8).toString(16).padStart(4, "0");
          const d3 = r.u16(ptr + 10).toString(16).padStart(4, "0");
          entry.guid = `${d1}-${d2}-${d3}-${hex(g.subarray(8, 10))}-${hex(g.subarray(10, 16))}`.toUpperCase();
          entry.age = r.u32(ptr + 20);
          entry.pdb = r.cstring(ptr + 24, 520);
        } else if (r.u32(ptr) === 0x3031424e) {
          // NB10
          entry.pdb = r.cstring(ptr + 16, 520);
        }
      }
      debug.push(entry);
    }
  }

  // TLS callbacks
  const tlsCallbacks: PeAnalysis["tlsCallbacks"] = [];
  const tlsDir = dir(9);
  if (tlsDir) {
    const off = rvaToOffset(tlsDir.rva);
    const cbField = is64 ? 24 : 12;
    if (off !== null && r.has(off + cbField, ptrSize)) {
      const cbVa = readPtr(off + cbField);
      if (cbVa) {
        const arr = rvaToOffset(Number(cbVa - imageBase));
        for (let i = 0; arr !== null && i < 64 && r.has(arr + i * ptrSize, ptrSize); i++) {
          const va = readPtr(arr + i * ptrSize);
          if (!va) break;
          const rva = Number(va - imageBase);
          tlsCallbacks.push({ va: `0x${va.toString(16)}`, rva, section: sectionFor(rva)?.name ?? null });
        }
      }
    }
  }

  // Load config
  let loadConfig: PeAnalysis["loadConfig"];
  const lcDir = dir(10);
  if (lcDir) {
    const off = rvaToOffset(lcDir.rva);
    if (off !== null && r.has(off, 4)) {
      const size = r.u32(off);
      const field = (o32: number, o64: number) => (is64 ? o64 : o32);
      const has = (o: number, n: number) => size >= o + n && r.has(off + o, n);
      const cookieAt = field(0x3c, 0x58);
      const sehAt = field(0x40, 0x60);
      const flagsAt = field(0x58, 0x90);
      loadConfig = {
        securityCookie: has(cookieAt, ptrSize) && readPtr(off + cookieAt) !== BigInt(0),
        sehTable: !is64 && has(sehAt, 4) && r.u32(off + sehAt) !== 0,
        cfgInstrumented: has(flagsAt, 4) && (r.u32(off + flagsAt) & 0x100) !== 0,
      };
    }
  }

  // Rich header
  let rich: PeAnalysis["rich"];
  const richEnd = Math.min(eLfanew, r.length - 8);
  for (let o = 0x80; o + 8 <= richEnd; o += 4) {
    if (r.u32(o) !== 0x68636952) continue; // "Rich"
    const key = r.u32(o + 4);
    let start = -1;
    for (let p = o - 4; p >= 0x80; p -= 4) {
      if ((r.u32(p) ^ key) === 0x536e6144) {
        // "DanS"
        start = p;
        break;
      }
    }
    if (start < 0) break;
    const entries: RichEntry[] = [];
    const clear = new Uint8Array(o - start);
    for (let p = start; p < o; p += 4) {
      const v = (r.u32(p) ^ key) >>> 0;
      new DataView(clear.buffer).setUint32(p - start, v, true);
    }
    for (let p = start + 16; p + 8 <= o; p += 8) {
      const compId = (r.u32(p) ^ key) >>> 0;
      const count = (r.u32(p + 4) ^ key) >>> 0;
      entries.push({ productId: compId >>> 16, build: compId & 0xffff, count });
    }
    let csum = start >>> 0;
    for (let i = 0; i < start; i++) {
      if (i >= 0x3c && i < 0x40) continue;
      csum = (csum + rol32(bytes[i], i)) >>> 0;
    }
    for (const e of entries) csum = (csum + rol32(((e.productId << 16) | e.build) >>> 0, e.count)) >>> 0;
    rich = { entries, key: `0x${key.toString(16).padStart(8, "0")}`, checksumValid: csum === key, hash: md5(clear), offset: start, size: o + 8 - start };
    break;
  }

  // Authenticode
  const secDir = directories[4];
  const signature: PeSignature = { present: false, offset: 0, size: 0, parsed: false, certificates: [], nestedSignatures: 0 };
  if (secDir && secDir.rva && secDir.size) {
    signature.present = true;
    signature.offset = secDir.rva; // a file offset, not an RVA
    signature.size = secDir.size;
    try {
      if (!r.has(secDir.rva, 8)) throw new ParseError("certificate table lies outside the file");
      const length = r.u32(secDir.rva);
      signature.revision = r.u16(secDir.rva + 4);
      signature.certificateType = r.u16(secDir.rva + 6);
      if (signature.certificateType !== 2) throw new ParseError(`certificate type ${signature.certificateType} is not PKCS#7 signed data`);
      const blob = r.slice(secDir.rva + 8, Math.min(length, secDir.size) - 8);
      Object.assign(signature, parseAuthenticode(blob));
      signature.parsed = true;
    } catch (err) {
      signature.error = err instanceof Error ? err.message : String(err);
    }
  }

  // Overlay: bytes after the last section's raw data (excluding a trailing certificate table)
  let overlay: PeAnalysis["overlay"];
  const endOfSections = sections.reduce((m, s) => Math.max(m, s.rawSize ? s.rawOffset + s.rawSize : 0), sizeOfHeaders);
  let overlayEnd = r.length;
  if (signature.present && signature.offset >= endOfSections && signature.offset + signature.size >= r.length - 8) overlayEnd = signature.offset;
  if (endOfSections < overlayEnd) {
    const data = bytes.subarray(endOfSections, overlayEnd);
    if (data.length >= 16) overlay = { offset: endOfSections, size: data.length, entropy: entropy(data), detected: identify(data) };
  }

  const computed = peChecksum(bytes, checksumOffset);
  const entrySection = sectionFor(entryPoint)?.name ?? null;
  const isDotNet = !!dir(14);

  return {
    format: is64 ? "PE32+" : "PE32",
    machine,
    machineName: MACHINES[machine] ?? `0x${machine.toString(16)}`,
    is64,
    isDll: (characteristicsValue & 0x2000) !== 0,
    isDriver: subsystemValue === 1 || (dllCharacteristicsValue & 0x2000) !== 0,
    isDotNet,
    timestamp,
    timestampIso: timestamp ? new Date(timestamp * 1000).toISOString() : null,
    reproducible,
    characteristics: flagsOf(characteristicsValue, FILE_FLAGS),
    dllCharacteristics: flagsOf(dllCharacteristicsValue, DLL_FLAGS),
    subsystem: SUBSYSTEMS[subsystemValue] ?? `Unknown (${subsystemValue})`,
    entryPoint,
    entrySection,
    imageBase: `0x${imageBase.toString(16)}`,
    sizeOfImage,
    sizeOfHeaders,
    linkerVersion,
    osVersion,
    checksum: { stored: storedChecksum, computed },
    eLfanew,
    headerOffsets: { dos: 0, pe: eLfanew, optional: opt, sectionTable },
    directories,
    sections,
    imports,
    exports,
    resources,
    version,
    manifest,
    debug,
    tlsCallbacks,
    loadConfig,
    rich,
    signature,
    overlay,
    imphash,
    imphashExact,
    importCount,
    anomalies,
  };
}

/** The PE optional-header checksum algorithm (as ImageHlp CheckSumMappedFile). */
export function peChecksum(bytes: Uint8Array, checksumOffset: number): number {
  let sum = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const n = bytes.length & ~1;
  for (let i = 0; i < n; i += 2) {
    if (i === checksumOffset || i === checksumOffset + 2) continue;
    sum += view.getUint16(i, true);
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  if (bytes.length & 1) {
    sum += bytes[bytes.length - 1];
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  sum = (sum & 0xffff) + (sum >>> 16);
  return (sum + bytes.length) >>> 0;
}

function parseVersionInfo(data: Uint8Array): Record<string, string> {
  const out: Record<string, string> = {};
  const r = new Reader(data);
  const align = (o: number) => (o + 3) & ~3;
  let budget = 512;
  const walk = (off: number, end: number, depth: number) => {
    while (off + 6 <= end && budget-- > 0 && depth < 6) {
      const wLength = r.u16(off);
      const wValueLength = r.u16(off + 2);
      const wType = r.u16(off + 4);
      if (wLength < 6 || off + wLength > end) return;
      let keyEnd = off + 6;
      while (keyEnd + 1 < off + wLength && (data[keyEnd] || data[keyEnd + 1])) keyEnd += 2;
      const key = r.utf16(off + 6, (keyEnd - off - 6) / 2);
      const valueOff = align(keyEnd + 2);
      if (depth === 3 && wType === 1 && wValueLength) {
        out[key] = r.utf16(valueOff, wValueLength).replace(/\0+$/, "").trim();
      }
      const childrenOff = align(valueOff + (wType === 1 ? wValueLength * 2 : wValueLength));
      if (key === "VS_VERSION_INFO" || key === "StringFileInfo" || depth === 2) walk(childrenOff, off + wLength, depth + 1);
      off = align(off + wLength);
    }
  };
  try {
    walk(0, data.length, 0);
  } catch {
    // Partial version info is still useful.
  }
  return out;
}

function parseManifest(data: Uint8Array): PeAnalysis["manifest"] {
  const raw = new TextDecoder("utf-8", { fatal: false }).decode(data.subarray(0, 64 * 1024));
  const level = /requestedExecutionLevel[^>]*level\s*=\s*["']([^"']+)["']/i.exec(raw)?.[1];
  const ui = /uiAccess\s*=\s*["'](true|false)["']/i.exec(raw)?.[1];
  return { raw, executionLevel: level, uiAccess: ui ? ui.toLowerCase() === "true" : undefined };
}

const DIGEST_BY_OID: Record<string, "MD5" | "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"> = {
  "1.2.840.113549.2.5": "MD5",
  "1.3.14.3.2.26": "SHA-1",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
};

function parseAuthenticode(blob: Uint8Array): Partial<PeSignature> {
  const contentInfo = parseDer(blob);
  const [ct, wrapped] = contentInfo.children ?? [];
  if (!ct || oid(ct) !== "1.2.840.113549.1.7.2") throw new ParseError("not a PKCS#7 SignedData structure");
  const signedData = wrapped?.children?.[0];
  const parts = signedData?.children ?? [];
  const encap = parts[2];
  const spc = encap?.children?.[1]?.children?.[0];
  const digestInfo = spc?.children?.[1];
  const algNode = digestInfo?.children?.[0]?.children?.[0];
  const digestNode = digestInfo?.children?.[1];
  const algOid = algNode ? oid(algNode) : "";

  const certificates: Certificate[] = [];
  const certSet = parts.find((p) => p.cls === "context" && p.tag === 0);
  for (const c of certSet?.children ?? []) {
    try {
      certificates.push(parseCertificate(blob, c));
    } catch {
      // Skip attribute certificates or malformed entries.
    }
    if (certificates.length >= 32) break;
  }

  const signerInfos = parts[parts.length - 1];
  const signerInfo = signerInfos?.children?.[0];
  let signer: Certificate | undefined;
  let programName: string | undefined;
  let moreInfoUrl: string | undefined;
  let signingTime: string | null | undefined;
  let nested = 0;
  if (signerInfo?.children) {
    const sid = signerInfo.children[1];
    const serial = sid?.children?.[1] ? integerHex(sid.children[1]) : undefined;
    signer = certificates.find((c) => c.serial === serial);
    const auth = signerInfo.children.find((c) => c.cls === "context" && c.tag === 0);
    for (const attr of auth?.children ?? []) {
      const type = attr.children?.[0] ? oid(attr.children[0]) : "";
      const value = attr.children?.[1]?.children?.[0];
      if (type === "1.3.6.1.4.1.311.2.1.12" && value?.children) {
        for (const f of value.children) {
          if (f.cls !== "context") continue;
          const inner = f.children?.[0];
          if (f.tag === 0 && inner) programName = inner.cls === "context" && inner.tag === 0 ? latinOrUtf16(inner) : text(inner);
          if (f.tag === 1 && inner && inner.cls === "context" && inner.tag === 0) moreInfoUrl = text(inner);
        }
      }
      if (type === "1.2.840.113549.1.9.5" && value) signingTime = time(value);
    }
    const unauth = signerInfo.children.find((c) => c.cls === "context" && c.tag === 1);
    for (const attr of unauth?.children ?? []) {
      const type = attr.children?.[0] ? oid(attr.children[0]) : "";
      if (type === "1.3.6.1.4.1.311.2.4.1") nested += attr.children?.[1]?.children?.length ?? 0;
      if (!signingTime && (type === "1.2.840.113549.1.9.6" || type === "1.3.6.1.4.1.311.3.3.1" || type === "1.2.840.113549.1.9.16.2.14")) signingTime = findSigningTime(attr);
    }
  }
  return {
    digestAlgorithm: DIGEST_BY_OID[algOid] ?? oidName(algOid),
    signedDigest: digestNode ? hex(digestNode.bytes) : undefined,
    programName,
    moreInfoUrl,
    signingTime,
    signer,
    certificates,
    nestedSignatures: nested,
  };
}

function latinOrUtf16(node: Asn1): string {
  // SpcString [0] IMPLICIT BMPString
  let s = "";
  for (let i = 0; i + 1 < node.bytes.length; i += 2) s += String.fromCharCode((node.bytes[i] << 8) | node.bytes[i + 1]);
  return s;
}

/** Depth-first search for a signingTime attribute or a TSTInfo genTime inside a countersignature. */
function findSigningTime(node: Asn1, depth = 0): string | null {
  if (depth > 12 || !node.children) return null;
  for (let i = 0; i < node.children.length; i++) {
    const c = node.children[i];
    if (c.cls === "universal" && c.tag === 6 && oid(c) === "1.2.840.113549.1.9.5") {
      const v = node.children[i + 1]?.children?.[0];
      if (v) return time(v);
    }
    if (c.cls === "universal" && c.tag === 0x18) return time(c);
    if (c.cls === "universal" && c.tag === 4 && !c.constructed && c.bytes.length > 16 && c.bytes[0] === 0x30) {
      try {
        const inner = parseDer(c.bytes);
        const t = findSigningTime(inner, depth + 1);
        if (t) return t;
      } catch {
        // not DER
      }
    }
    const t = findSigningTime(c, depth + 1);
    if (t) return t;
  }
  return null;
}

/**
 * Authenticode image hash: the whole file except the checksum field, the
 * security directory entry and the certificate table.
 */
export async function authenticodeDigest(bytes: Uint8Array, pe: PeAnalysis): Promise<string | null> {
  const alg = pe.signature.digestAlgorithm;
  if (!pe.signature.present || !alg || !["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"].includes(alg)) return null;
  const checksumOffset = pe.headerOffsets.optional + 64;
  const secEntry = (pe.is64 ? pe.headerOffsets.optional + 112 : pe.headerOffsets.optional + 96) + 4 * 8;
  const certStart = pe.signature.offset;
  const certEnd = Math.min(bytes.length, pe.signature.offset + pe.signature.size);
  if (!(checksumOffset < secEntry && secEntry + 8 <= certStart)) return null;
  const parts = [bytes.subarray(0, checksumOffset), bytes.subarray(checksumOffset + 4, secEntry), bytes.subarray(secEntry + 8, certStart), bytes.subarray(certEnd)];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const joined = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    joined.set(p, o);
    o += p.length;
  }
  if (alg === "MD5") return md5(joined);
  const buf = await crypto.subtle.digest(alg, joined as unknown as BufferSource);
  return hex(new Uint8Array(buf));
}

