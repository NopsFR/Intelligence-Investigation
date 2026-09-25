import { ParseError, Reader, entropy, hex } from "./bytes";

// ELF static parser: headers, segments, sections, symbols, dynamic section,
// relocations, notes and the hardening properties `checksec` reports.

const MAX_PH = 256;
const MAX_SH = 1024;
const MAX_SYMBOLS = 50_000;
const MAX_RELOCS = 20_000;

export const ELF_MACHINES: Record<number, string> = {
  2: "SPARC",
  3: "x86 (i386)",
  8: "MIPS",
  20: "PowerPC",
  21: "PowerPC 64",
  22: "IBM S/390",
  40: "ARM (32-bit)",
  42: "SuperH",
  43: "SPARC v9",
  50: "IA-64",
  62: "x86-64",
  183: "AArch64",
  243: "RISC-V",
  247: "eBPF",
  258: "LoongArch",
};

const ELF_TYPES: Record<number, string> = { 0: "NONE", 1: "REL (relocatable object)", 2: "EXEC (executable)", 3: "DYN (shared object / PIE)", 4: "CORE (core dump)" };
const OSABI: Record<number, string> = { 0: "System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux (GNU)", 6: "Solaris", 7: "AIX", 8: "IRIX", 9: "FreeBSD", 12: "OpenBSD", 97: "ARM EABI", 255: "Standalone" };

export const PT_TYPES: Record<number, string> = {
  0: "NULL",
  1: "LOAD",
  2: "DYNAMIC",
  3: "INTERP",
  4: "NOTE",
  5: "SHLIB",
  6: "PHDR",
  7: "TLS",
  0x6474e550: "GNU_EH_FRAME",
  0x6474e551: "GNU_STACK",
  0x6474e552: "GNU_RELRO",
  0x6474e553: "GNU_PROPERTY",
  0x70000001: "ARM_EXIDX",
};

export const SH_TYPES: Record<number, string> = {
  0: "NULL",
  1: "PROGBITS",
  2: "SYMTAB",
  3: "STRTAB",
  4: "RELA",
  5: "HASH",
  6: "DYNAMIC",
  7: "NOTE",
  8: "NOBITS",
  9: "REL",
  11: "DYNSYM",
  14: "INIT_ARRAY",
  15: "FINI_ARRAY",
  16: "PREINIT_ARRAY",
  17: "GROUP",
  0x6ffffff6: "GNU_HASH",
  0x6ffffffd: "VERDEF",
  0x6ffffffe: "VERNEED",
  0x6fffffff: "VERSYM",
};

const X86_64_RELOCS: Record<number, string> = { 1: "R_X86_64_64", 2: "R_X86_64_PC32", 5: "R_X86_64_COPY", 6: "R_X86_64_GLOB_DAT", 7: "R_X86_64_JUMP_SLOT", 8: "R_X86_64_RELATIVE", 16: "R_X86_64_DTPMOD64", 18: "R_X86_64_TPOFF64", 37: "R_X86_64_IRELATIVE" };
const AARCH64_RELOCS: Record<number, string> = { 257: "R_AARCH64_ABS64", 1024: "R_AARCH64_COPY", 1025: "R_AARCH64_GLOB_DAT", 1026: "R_AARCH64_JUMP_SLOT", 1027: "R_AARCH64_RELATIVE", 1032: "R_AARCH64_IRELATIVE" };
const I386_RELOCS: Record<number, string> = { 1: "R_386_32", 2: "R_386_PC32", 5: "R_386_COPY", 6: "R_386_GLOB_DAT", 7: "R_386_JMP_SLOT", 8: "R_386_RELATIVE" };

export interface ElfSegment {
  type: string;
  offset: number;
  vaddr: string;
  fileSize: number;
  memSize: number;
  flags: string;
}

export interface ElfSection {
  index: number;
  name: string;
  type: string;
  flags: string;
  addr: string;
  offset: number;
  size: number;
  entropy: number | null;
}

export interface ElfSymbol {
  name: string;
  value: string;
  size: number;
  type: string;
  bind: string;
  section: string;
  version?: string;
}

export interface ElfRelocation {
  section: string;
  offset: string;
  type: string;
  symbol: string;
  addend?: string;
}

export interface ElfNote {
  owner: string;
  type: number;
  description: string;
}

export interface ElfAnalysis {
  class: "ELF32" | "ELF64";
  endianness: "little" | "big";
  osAbi: string;
  type: string;
  machine: string;
  entry: string;
  interpreter?: string;
  segments: ElfSegment[];
  sections: ElfSection[];
  needed: string[];
  soname?: string;
  rpath?: string;
  runpath?: string;
  imports: ElfSymbol[];
  exports: ElfSymbol[];
  symbols: ElfSymbol[];
  symbolsTruncated: boolean;
  relocations: ElfRelocation[];
  relocationCounts: Record<string, number>;
  notes: ElfNote[];
  buildId?: string;
  stripped: boolean;
  staticallyLinked: boolean;
  packer?: string;
  checksec: {
    nx: boolean;
    pie: "yes" | "no" | "shared-object";
    relro: "full" | "partial" | "none";
    canary: boolean;
    fortify: boolean;
    fortifiedFunctions: string[];
    rpath: boolean;
  };
  anomalies: string[];
}

const SYM_TYPES = ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS"];
const SYM_BINDS = ["LOCAL", "GLOBAL", "WEAK"];

function pflags(f: number): string {
  return `${f & 4 ? "R" : "-"}${f & 2 ? "W" : "-"}${f & 1 ? "X" : "-"}`;
}

function shflags(f: number): string {
  return `${f & 2 ? "A" : ""}${f & 1 ? "W" : ""}${f & 4 ? "X" : ""}${f & 0x10 ? "M" : ""}${f & 0x20 ? "S" : ""}${f & 0x400 ? "T" : ""}` || "-";
}

export function parseElf(bytes: Uint8Array): ElfAnalysis {
  if (bytes.length < 52 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) throw new ParseError("No ELF magic");
  const cls = bytes[4];
  const data = bytes[5];
  if (cls !== 1 && cls !== 2) throw new ParseError(`Invalid ELF class ${cls}`);
  if (data !== 1 && data !== 2) throw new ParseError(`Invalid ELF data encoding ${data}`);
  const is64 = cls === 2;
  const r = new Reader(bytes, data === 1);
  const anomalies: string[] = [];
  const addr = (o: number) => (is64 ? r.u64(o) : BigInt(r.u32(o)));
  const off = (o: number) => (is64 ? r.u64n(o) : r.u32(o));
  const hx = (v: bigint | number) => `0x${v.toString(16)}`;

  const eType = r.u16(16);
  const eMachine = r.u16(18);
  const entry = addr(24);
  const phoff = off(is64 ? 32 : 28);
  const shoff = off(is64 ? 40 : 32);
  const phentsize = r.u16(is64 ? 54 : 42);
  const phnum = r.u16(is64 ? 56 : 44);
  const shentsize = r.u16(is64 ? 58 : 46);
  let shnum = r.u16(is64 ? 60 : 48);
  let shstrndx = r.u16(is64 ? 62 : 50);

  // Extended numbering: counts live in section header 0.
  if (shoff && r.has(shoff, shentsize)) {
    if (shnum === 0) shnum = Number(is64 ? r.u64(shoff + 32) : BigInt(r.u32(shoff + 20)));
    if (shstrndx === 0xffff) shstrndx = r.u32(shoff + (is64 ? 44 : 28));
  }

  // Program headers
  const segments: ElfSegment[] = [];
  const rawSegments: { type: number; offset: number; vaddr: bigint; filesz: number; flags: number }[] = [];
  if (phoff && phnum) {
    if (phentsize < (is64 ? 56 : 32)) anomalies.push(`Program header entry size ${phentsize} is smaller than the ELF${is64 ? 64 : 32} structure`);
    for (let i = 0; i < Math.min(phnum, MAX_PH); i++) {
      const o = phoff + i * phentsize;
      if (!r.has(o, is64 ? 56 : 32)) {
        anomalies.push("Program header table is truncated");
        break;
      }
      const type = r.u32(o);
      const flags = is64 ? r.u32(o + 4) : r.u32(o + 24);
      const offset = is64 ? r.u64n(o + 8) : r.u32(o + 4);
      const vaddr = is64 ? r.u64(o + 16) : BigInt(r.u32(o + 8));
      const filesz = is64 ? r.u64n(o + 32) : r.u32(o + 16);
      const memsz = is64 ? r.u64n(o + 40) : r.u32(o + 20);
      rawSegments.push({ type, offset, vaddr, filesz, flags });
      segments.push({ type: PT_TYPES[type] ?? hx(type), offset, vaddr: hx(vaddr), fileSize: filesz, memSize: memsz, flags: pflags(flags) });
    }
  }

  // Section headers
  const rawSections: { name: number; type: number; flags: number; addr: bigint; offset: number; size: number; link: number; info: number; entsize: number }[] = [];
  if (shoff && shnum) {
    if (shnum > MAX_SH) anomalies.push(`${shnum} sections declared; only the first ${MAX_SH} are read`);
    for (let i = 0; i < Math.min(shnum, MAX_SH); i++) {
      const o = shoff + i * shentsize;
      if (!r.has(o, is64 ? 64 : 40)) {
        anomalies.push("Section header table is truncated or points outside the file");
        break;
      }
      rawSections.push({
        name: r.u32(o),
        type: r.u32(o + 4),
        flags: Number(is64 ? r.u64(o + 8) & BigInt(0xffffffff) : BigInt(r.u32(o + 8))),
        addr: is64 ? r.u64(o + 16) : BigInt(r.u32(o + 12)),
        offset: is64 ? r.u64n(o + 24) : r.u32(o + 16),
        size: is64 ? r.u64n(o + 32) : r.u32(o + 20),
        link: r.u32(o + (is64 ? 40 : 24)),
        info: r.u32(o + (is64 ? 44 : 28)),
        entsize: is64 ? r.u64n(o + 56) : r.u32(o + 36),
      });
    }
  }
  const shstr = rawSections[shstrndx];
  const secName = (n: number) => (shstr && shstr.offset + n < r.length ? r.cstring(shstr.offset + n, 128) : "");
  const sections: ElfSection[] = rawSections.map((s, index) => {
    const inFile = s.type !== 8 && s.size > 0 && r.has(s.offset, Math.min(s.size, r.length - s.offset)) && s.offset < r.length;
    return {
      index,
      name: secName(s.name),
      type: SH_TYPES[s.type] ?? hx(s.type),
      flags: shflags(s.flags),
      addr: hx(s.addr),
      offset: s.offset,
      size: s.size,
      entropy: inFile ? entropy(bytes, s.offset, Math.min(r.length, s.offset + s.size)) : null,
    };
  });
  for (const s of rawSections) if (s.type !== 8 && s.size && s.offset + s.size > r.length) anomalies.push(`Section ${secName(s.name) || "?"} extends past the end of the file`);

  const vaddrToOffset = (v: bigint): number | null => {
    for (const s of rawSegments) {
      if (s.type !== 1) continue;
      if (v >= s.vaddr && v < s.vaddr + BigInt(s.filesz)) return s.offset + Number(v - s.vaddr);
    }
    return null;
  };

  // Symbols (with symbol-version names for dynsym)
  const symbols: ElfSymbol[] = [];
  let symbolsTruncated = false;
  const readSymbols = (secIndex: number): ElfSymbol[] => {
    const s = rawSections[secIndex];
    const strtab = rawSections[s.link];
    const size = is64 ? 24 : 16;
    const out: ElfSymbol[] = [];
    if (!strtab) return out;
    const n = Math.floor(s.size / size);
    for (let i = 0; i < n; i++) {
      if (symbols.length + out.length >= MAX_SYMBOLS) {
        symbolsTruncated = true;
        break;
      }
      const o = s.offset + i * size;
      if (!r.has(o, size)) break;
      const nameOff = r.u32(o);
      const info = is64 ? r.u8(o + 4) : r.u8(o + 12);
      const shndx = is64 ? r.u16(o + 6) : r.u16(o + 14);
      const value = is64 ? r.u64(o + 8) : BigInt(r.u32(o + 4));
      const sz = is64 ? r.u64n(o + 16) : r.u32(o + 8);
      out.push({
        name: strtab.offset + nameOff < r.length ? r.cstring(strtab.offset + nameOff, 256) : "",
        value: hx(value),
        size: sz,
        type: SYM_TYPES[info & 0xf] ?? String(info & 0xf),
        bind: SYM_BINDS[info >> 4] ?? String(info >> 4),
        section: shndx === 0 ? "UND" : shndx === 0xfff1 ? "ABS" : shndx === 0xfff2 ? "COMMON" : String(shndx),
      });
    }
    return out;
  };
  const dynsymIndex = rawSections.findIndex((s) => s.type === 11);
  const symtabIndex = rawSections.findIndex((s) => s.type === 2);
  const dynsym = dynsymIndex >= 0 ? readSymbols(dynsymIndex) : [];
  const symtab = symtabIndex >= 0 ? readSymbols(symtabIndex) : [];

  // Attach GNU symbol versions (VERSYM + VERNEED) to dynamic symbols.
  const versym = rawSections.find((s) => s.type === 0x6fffffff);
  const verneed = rawSections.find((s) => s.type === 0x6ffffffe);
  if (versym && verneed && dynsym.length) {
    const names = new Map<number, string>();
    const strtab = rawSections[verneed.link];
    let o = verneed.offset;
    for (let guard = 0; guard < 256 && strtab && r.has(o, 16); guard++) {
      const cnt = r.u16(o + 2);
      const aux = r.u32(o + 8);
      const next = r.u32(o + 12);
      let a = o + aux;
      for (let j = 0; j < Math.min(cnt, 256) && r.has(a, 16); j++) {
        names.set(r.u16(a + 6) & 0x7fff, r.cstring(strtab.offset + r.u32(a + 8), 64));
        const an = r.u32(a + 12);
        if (!an) break;
        a += an;
      }
      if (!next) break;
      o += next;
    }
    dynsym.forEach((sym, i) => {
      const vo = versym.offset + i * 2;
      if (!r.has(vo, 2)) return;
      const v = names.get(r.u16(vo) & 0x7fff);
      if (v) sym.version = v;
    });
  }
  symbols.push(...symtab, ...dynsym);
  const dynamicSource = dynsym.length ? dynsym : symtab;
  const imports = dynamicSource.filter((s) => s.section === "UND" && s.name);
  const exports = dynamicSource.filter((s) => s.section !== "UND" && s.name && (s.bind === "GLOBAL" || s.bind === "WEAK") && (s.type === "FUNC" || s.type === "OBJECT"));

  // Dynamic section
  const needed: string[] = [];
  let soname: string | undefined;
  let rpath: string | undefined;
  let runpath: string | undefined;
  let bindNow = false;
  let pieFlag = false;
  const dynSeg = rawSegments.find((s) => s.type === 2);
  const dynSec = rawSections.find((s) => s.type === 6);
  const dynOffset = dynSec?.offset ?? dynSeg?.offset;
  const dynSize = dynSec?.size ?? dynSeg?.filesz ?? 0;
  if (dynOffset !== undefined && dynSize) {
    const entSize = is64 ? 16 : 8;
    const entries: { tag: number; val: bigint }[] = [];
    for (let i = 0; i < Math.min(Math.floor(dynSize / entSize), 1024); i++) {
      const o = dynOffset + i * entSize;
      if (!r.has(o, entSize)) break;
      const tag = is64 ? Number(r.u64(o) & BigInt(0xffffffff)) : r.u32(o);
      const val = is64 ? r.u64(o + 8) : BigInt(r.u32(o + 4));
      if (tag === 0) break;
      entries.push({ tag, val });
    }
    const strtabVa = entries.find((e) => e.tag === 5)?.val;
    const dynstrSection = dynSec ? rawSections[dynSec.link] : undefined;
    const strBase = dynstrSection?.offset ?? (strtabVa !== undefined ? vaddrToOffset(strtabVa) : null);
    const str = (v: bigint) => (strBase !== null && strBase !== undefined ? r.cstring(strBase + Number(v), 512) : "");
    for (const e of entries) {
      if (e.tag === 1) needed.push(str(e.val));
      else if (e.tag === 14) soname = str(e.val);
      else if (e.tag === 15) rpath = str(e.val);
      else if (e.tag === 29) runpath = str(e.val);
      else if (e.tag === 24) bindNow = true;
      else if (e.tag === 30 && (e.val & BigInt(0x8)) !== BigInt(0)) bindNow = true;
      else if (e.tag === 0x6ffffffb) {
        if ((e.val & BigInt(0x1)) !== BigInt(0)) bindNow = true;
        if ((e.val & BigInt(0x08000000)) !== BigInt(0)) pieFlag = true;
      }
    }
  }

  // Relocations
  const relocations: ElfRelocation[] = [];
  const relocationCounts: Record<string, number> = {};
  const relocNames = eMachine === 62 ? X86_64_RELOCS : eMachine === 183 ? AARCH64_RELOCS : eMachine === 3 ? I386_RELOCS : {};
  rawSections.forEach((s) => {
    if (s.type !== 4 && s.type !== 9) return;
    const isRela = s.type === 4;
    const size = is64 ? (isRela ? 24 : 16) : isRela ? 12 : 8;
    const name = secName(s.name);
    const n = Math.floor(s.size / size);
    relocationCounts[name] = n;
    const symSec = rawSections[s.link];
    const symList = symSec?.type === 11 ? dynsym : symSec?.type === 2 ? symtab : [];
    for (let i = 0; i < n && relocations.length < MAX_RELOCS; i++) {
      const o = s.offset + i * size;
      if (!r.has(o, size)) break;
      const offset = is64 ? r.u64(o) : BigInt(r.u32(o));
      const info = is64 ? r.u64(o + 8) : BigInt(r.u32(o + 4));
      const symIndex = Number(is64 ? info >> BigInt(32) : info >> BigInt(8));
      const type = Number(is64 ? info & BigInt(0xffffffff) : info & BigInt(0xff));
      const addend = isRela ? (is64 ? r.u64(o + 16) : BigInt(r.i32(o + 8))) : undefined;
      relocations.push({ section: name, offset: hx(offset), type: relocNames[type] ?? String(type), symbol: symList[symIndex]?.name ?? "", addend: addend !== undefined ? hx(addend) : undefined });
    }
  });

  // Notes
  const notes: ElfNote[] = [];
  let buildId: string | undefined;
  const noteRanges = rawSections.filter((s) => s.type === 7).map((s) => ({ offset: s.offset, size: s.size }));
  if (!noteRanges.length) for (const s of rawSegments) if (s.type === 4) noteRanges.push({ offset: s.offset, size: s.filesz });
  for (const range of noteRanges) {
    let o = range.offset;
    const end = Math.min(r.length, range.offset + range.size);
    for (let guard = 0; guard < 64 && o + 12 <= end; guard++) {
      const namesz = r.u32(o);
      const descsz = r.u32(o + 4);
      const type = r.u32(o + 8);
      const nameOff = o + 12;
      const descOff = nameOff + ((namesz + 3) & ~3);
      if (descOff + descsz > end || namesz > 256 || descsz > 4096) break;
      const owner = r.cstring(nameOff, namesz);
      const desc = r.slice(descOff, descsz);
      let description = hex(desc.subarray(0, 64));
      if (owner === "GNU" && type === 3) {
        buildId = hex(desc);
        description = buildId;
      } else if (owner === "GNU" && type === 1 && descsz >= 16) {
        const os = ["Linux", "GNU", "Solaris", "FreeBSD"][r.u32(descOff)] ?? `os ${r.u32(descOff)}`;
        description = `ABI tag: ${os} ${r.u32(descOff + 4)}.${r.u32(descOff + 8)}.${r.u32(descOff + 12)}`;
      } else if (owner === "GNU" && type === 5) description = "GNU property (CET / BTI / PAC flags)";
      else if (owner === "Go" && type === 4) description = `Go build ID ${latin(desc)}`;
      notes.push({ owner, type, description });
      o = descOff + ((descsz + 3) & ~3);
    }
  }

  const interpSeg = rawSegments.find((s) => s.type === 3);
  const interpreter = interpSeg && r.has(interpSeg.offset, 1) ? r.cstring(interpSeg.offset, 256) : undefined;
  const stackSeg = rawSegments.find((s) => s.type === 0x6474e551);
  const hasRelro = rawSegments.some((s) => s.type === 0x6474e552);
  const allSymbolNames = new Set(symbols.map((s) => s.name));
  const fortifiedFunctions = [...allSymbolNames].filter((n) => /^__\w+_chk$/.test(n) && n !== "__stack_chk_fail");

  // UPX leaves its magic in the first few hundred bytes of packed ELF files.
  let packer: string | undefined;
  const head = bytes.subarray(0, Math.min(bytes.length, 1024));
  for (let i = 0; i + 4 <= head.length; i++) {
    if (head[i] === 0x55 && head[i + 1] === 0x50 && head[i + 2] === 0x58 && head[i + 3] === 0x21) {
      packer = "UPX";
      break;
    }
  }

  const pie: ElfAnalysis["checksec"]["pie"] = eType === 3 ? (interpreter || pieFlag ? "yes" : "shared-object") : "no";

  return {
    class: is64 ? "ELF64" : "ELF32",
    endianness: data === 1 ? "little" : "big",
    osAbi: OSABI[bytes[7]] ?? `ABI ${bytes[7]}`,
    type: ELF_TYPES[eType] ?? hx(eType),
    machine: ELF_MACHINES[eMachine] ?? `machine ${eMachine}`,
    entry: hx(entry),
    interpreter,
    segments,
    sections,
    needed,
    soname,
    rpath,
    runpath,
    imports,
    exports,
    symbols,
    symbolsTruncated,
    relocations,
    relocationCounts,
    notes,
    buildId,
    stripped: symtabIndex < 0,
    staticallyLinked: !interpreter && !dynSeg && eType === 2,
    packer,
    checksec: {
      nx: stackSeg ? (stackSeg.flags & 1) === 0 : false,
      pie,
      relro: hasRelro ? (bindNow ? "full" : "partial") : "none",
      canary: allSymbolNames.has("__stack_chk_fail") || allSymbolNames.has("__stack_chk_guard") || allSymbolNames.has("__intel_security_cookie"),
      fortify: fortifiedFunctions.length > 0,
      fortifiedFunctions,
      rpath: !!(rpath || runpath),
    },
    anomalies: [...anomalies, ...(shnum === 0 && eType !== 4 ? ["No section headers (stripped section table, common after packing)"] : [])],
  };
}

function latin(b: Uint8Array): string {
  let s = "";
  for (const c of b.subarray(0, 128)) s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : "";
  return s;
}
