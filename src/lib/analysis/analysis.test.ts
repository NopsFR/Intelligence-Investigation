import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeFile } from "./analyze";
import { matchCapabilities } from "./apis";
import { ParseError, Reader, entropy } from "./bytes";
import { certificatesFromPem, parseDer } from "./der";
import { parseElf } from "./elf";
import { fileHashes, md5 } from "./hash";
import { identify } from "./magic";
import { parseMacho } from "./macho";
import { parsePe, peChecksum } from "./pe";
import { extractStrings } from "./strings";

const enc = (s: string) => new TextEncoder().encode(s);

/** Minimal PE32+ with one .text section and a kernel32 import table. */
function buildPe(opts: { imports?: string[]; sectionName?: string; characteristics?: number; entry?: number } = {}) {
  const imports = opts.imports ?? ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
  const b = new Uint8Array(0x400);
  const v = new DataView(b.buffer);
  b.set(enc("MZ"), 0);
  v.setUint32(0x3c, 0x80, true);
  b.set(enc("PE\0\0"), 0x80);
  const coff = 0x84;
  v.setUint16(coff, 0x8664, true);
  v.setUint16(coff + 2, 1, true);
  v.setUint32(coff + 4, 1_700_000_000, true);
  v.setUint16(coff + 16, 0xf0, true);
  v.setUint16(coff + 18, 0x22, true);
  const opt = 0x98;
  v.setUint16(opt, 0x20b, true);
  v.setUint32(opt + 16, opts.entry ?? 0x1000, true);
  v.setBigUint64(opt + 24, BigInt("0x140000000"), true);
  v.setUint32(opt + 32, 0x1000, true);
  v.setUint32(opt + 36, 0x200, true);
  v.setUint32(opt + 56, 0x2000, true);
  v.setUint32(opt + 60, 0x200, true);
  v.setUint16(opt + 68, 3, true);
  v.setUint16(opt + 70, 0x8160, true);
  v.setUint32(opt + 108, 16, true);
  v.setUint32(opt + 112 + 8, 0x1100, true); // import directory RVA
  v.setUint32(opt + 112 + 12, 40, true);
  const sec = opt + 0xf0;
  b.set(enc((opts.sectionName ?? ".text").padEnd(8, "\0")), sec);
  v.setUint32(sec + 8, 0x1000, true);
  v.setUint32(sec + 12, 0x1000, true);
  v.setUint32(sec + 16, 0x200, true);
  v.setUint32(sec + 20, 0x200, true);
  v.setUint32(sec + 36, opts.characteristics ?? 0x60000020, true);
  const off = (rva: number) => rva - 0x1000 + 0x200;
  b[off(0x1000)] = 0xc3;
  // import descriptor
  v.setUint32(off(0x1100), 0x1140, true);
  v.setUint32(off(0x1100) + 12, 0x1180, true);
  v.setUint32(off(0x1100) + 16, 0x1160, true);
  b.set(enc("kernel32.dll\0"), off(0x1180));
  let name = 0x1190;
  imports.forEach((fn, i) => {
    v.setBigUint64(off(0x1140) + i * 8, BigInt(name), true);
    v.setBigUint64(off(0x1160) + i * 8, BigInt(name), true);
    b.set(enc(`${fn}\0`), off(name) + 2);
    name += (2 + fn.length + 1 + 7) & ~7;
  });
  return b;
}

/** Minimal ELF64 executable: one RWX PT_LOAD, no section headers, UPX marker. */
function buildElf() {
  const b = new Uint8Array(0x200);
  const v = new DataView(b.buffer);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  v.setUint16(16, 2, true); // EXEC
  v.setUint16(18, 62, true); // x86-64
  v.setUint32(20, 1, true);
  v.setBigUint64(24, BigInt(0x400078), true);
  v.setBigUint64(32, BigInt(64), true); // phoff
  v.setUint16(52, 64, true);
  v.setUint16(54, 56, true);
  v.setUint16(56, 1, true);
  v.setUint16(58, 64, true);
  const ph = 64;
  v.setUint32(ph, 1, true); // LOAD
  v.setUint32(ph + 4, 7, true); // RWX
  v.setBigUint64(ph + 16, BigInt(0x400000), true);
  v.setBigUint64(ph + 32, BigInt(0x200), true);
  v.setBigUint64(ph + 40, BigInt(0x200), true);
  b.set(enc("UPX!"), 0x80);
  return b;
}

describe("hashing", () => {
  it("matches RFC 1321 MD5 vectors", () => {
    expect(md5(enc(""))).toBe("d41d8cd98f00b204e9800998ecf8427e");
    expect(md5(enc("abc"))).toBe("900150983cd24fb0d6963f7d28e17f72");
    expect(md5(enc("The quick brown fox jumps over the lazy dog"))).toBe("9e107d9d372bb6826bd81d3542a419d6");
  });

  it("agrees with Node's MD5 across block boundaries", () => {
    for (const n of [55, 56, 63, 64, 65, 119, 120, 1000, 65_537]) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 31 + 7) & 0xff);
      expect(md5(data)).toBe(createHash("md5").update(data).digest("hex"));
    }
  });

  it("computes the SHA family with WebCrypto", async () => {
    const h = await fileHashes(enc("abc"));
    expect(h.sha1).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
    expect(h.sha256).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

describe("byte primitives", () => {
  it("measures entropy between 0 and 8 bits per byte", () => {
    expect(entropy(new Uint8Array(1024))).toBe(0);
    expect(entropy(Uint8Array.from({ length: 256 }, (_, i) => i))).toBeCloseTo(8, 5);
  });

  it("rejects out-of-bounds reads with a ParseError", () => {
    const r = new Reader(new Uint8Array(4));
    expect(r.u32(0)).toBe(0);
    expect(() => r.u32(1)).toThrow(ParseError);
    expect(() => r.u16(-1)).toThrow(ParseError);
  });
});

describe("file identification", () => {
  it("identifies formats from content, not names", () => {
    expect(identify(buildPe()).id).toBe("pe");
    expect(identify(buildElf()).id).toBe("elf");
    expect(identify(enc("%PDF-1.7\n")).id).toBe("pdf");
    expect(identify(Uint8Array.from([0x50, 0x4b, 0x03, 0x04, 0, 0])).id).toBe("zip");
    expect(identify(Uint8Array.from([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0])).analyzer).toBe("pcap");
    expect(identify(enc("#!/bin/bash\necho hi\n")).id).toBe("shell");
    expect(identify(Uint8Array.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, ...new Array(24).fill(0)])).id).toBe("macho-fat");
    expect(identify(Uint8Array.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, ...new Array(24).fill(0)])).id).toBe("java-class");
  });
});

describe("strings", () => {
  it("extracts ASCII and UTF-16LE runs with tags", () => {
    const utf16 = Uint8Array.from([..."C:\\Windows\\evil.exe"].flatMap((c) => [c.charCodeAt(0), 0]));
    const data = new Uint8Array([...enc("\0\0http://malicious.example.net/payload\0\0"), ...utf16, 0, 0]);
    const s = extractStrings(data);
    expect(s.find((x) => x.encoding === "ascii")?.tags).toContain("url");
    expect(s.find((x) => x.encoding === "utf16le")).toMatchObject({ value: "C:\\Windows\\evil.exe", tags: expect.arrayContaining(["path"]) });
  });
});

describe("PE parser", () => {
  it("parses headers, sections and imports", () => {
    const pe = parsePe(buildPe());
    expect(pe.format).toBe("PE32+");
    expect(pe.machineName).toMatch(/x86-64/);
    expect(pe.sections).toHaveLength(1);
    expect(pe.entrySection).toBe(".text");
    expect(pe.dllCharacteristics).toEqual(expect.arrayContaining(["DYNAMIC_BASE", "NX_COMPAT", "HIGH_ENTROPY_VA"]));
    expect(pe.imports[0].dll).toBe("kernel32.dll");
    expect(pe.imports[0].functions.map((f) => f.name)).toEqual(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
  });

  it("computes a pefile-compatible imphash", () => {
    const pe = parsePe(buildPe());
    expect(pe.imphash).toBe(md5(enc("kernel32.virtualallocex,kernel32.writeprocessmemory,kernel32.createremotethread")));
    expect(pe.imphashExact).toBe(true);
  });

  it("computes the optional-header checksum excluding its own field", () => {
    const b = buildPe();
    const before = peChecksum(b, 0x98 + 64);
    new DataView(b.buffer).setUint32(0x98 + 64, 0xdeadbeef, true);
    expect(peChecksum(b, 0x98 + 64)).toBe(before);
  });

  it("refuses an MZ file without a PE header", () => {
    const b = new Uint8Array(128);
    b.set(enc("MZ"));
    expect(() => parsePe(b)).toThrow(/PE header|PE signature/);
  });

  it("survives truncation without throwing out-of-range errors", () => {
    const full = buildPe();
    for (const n of [0x90, 0x100, 0x190, 0x1b0, 0x300, 0x350]) {
      try {
        parsePe(full.subarray(0, n));
      } catch (err) {
        expect(err).toBeInstanceOf(ParseError);
      }
    }
  });
});

describe("capability rules", () => {
  it("requires every group of a rule", () => {
    expect(matchCapabilities(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]).map((h) => h.rule.id)).toContain("cap.remote-injection");
    expect(matchCapabilities(["VirtualAllocEx", "WriteProcessMemory"]).map((h) => h.rule.id)).not.toContain("cap.remote-injection");
  });
});

describe("analyzeFile", () => {
  it("reports capability and masquerade findings with evidence", async () => {
    const r = await analyzeFile(buildPe(), "invoice.pdf.exe");
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain("cap.remote-injection");
    expect(ids).toContain("file.double-extension");
    expect(ids).toContain("pe.unsigned");
    const inj = r.findings.find((f) => f.id === "cap.remote-injection")!;
    expect(inj.attack).toEqual(["T1055"]);
    expect(inj.evidence).toEqual(expect.arrayContaining(["imports CreateRemoteThread"]));
    expect(r.hashes.md5).toBe(createHash("md5").update(buildPe()).digest("hex"));
  });

  it("flags a writable, executable, packed section", async () => {
    const r = await analyzeFile(buildPe({ sectionName: "UPX1", characteristics: 0xe0000020 }), "sample.exe");
    const ids = r.findings.map((f) => f.id);
    expect(ids).toContain("pe.packer");
    expect(ids).toContain("pe.wx-section");
  });

  it("flags an executable disguised by extension", async () => {
    const r = await analyzeFile(buildPe({ imports: ["ExitProcess"] }), "report.pdf");
    expect(r.findings.find((f) => f.id === "file.extension-mismatch")?.severity).toBe("HIGH");
  });

  it("does not invent findings for plain text", async () => {
    const r = await analyzeFile(enc("hello world, nothing to see here\n"), "note.txt");
    expect(r.findings.filter((f) => f.severity !== "INFO")).toHaveLength(0);
  });
});

describe("ELF parser", () => {
  it("reads segments and hardening properties", () => {
    const elf = parseElf(buildElf());
    expect(elf.class).toBe("ELF64");
    expect(elf.machine).toBe("x86-64");
    expect(elf.segments[0]).toMatchObject({ type: "LOAD", flags: "RWX" });
    expect(elf.checksec.nx).toBe(false);
    expect(elf.checksec.pie).toBe("no");
    expect(elf.packer).toBe("UPX");
    expect(elf.anomalies.join(" ")).toMatch(/No section headers/);
  });

  it("turns structure into findings", async () => {
    const r = await analyzeFile(buildElf(), "bot");
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["elf.packer", "elf.rwx-segment", "elf.exec-stack"]));
  });
});

describe("Mach-O parser", () => {
  it("parses a thin 64-bit header with a dylib and PIE flag", () => {
    const b = new Uint8Array(0x200);
    const v = new DataView(b.buffer);
    v.setUint32(0, 0xfeedfacf, true);
    v.setUint32(4, 0x0100000c, true); // ARM64
    v.setUint32(12, 2, true); // executable
    v.setUint32(16, 1, true);
    v.setUint32(24, 0x200085, true);
    const lc = 32;
    v.setUint32(lc, 0xc, true);
    v.setUint32(lc + 4, 56, true);
    v.setUint32(lc + 8, 24, true);
    v.setUint32(lc + 16, 0x10000, true);
    b.set(enc("/usr/lib/libSystem.B.dylib\0"), lc + 24);
    const m = parseMacho(b);
    expect(m.fat).toBe(false);
    expect(m.slices[0]).toMatchObject({ cpu: "ARM64", fileType: "Executable" });
    expect(m.slices[0].flags).toContain("PIE");
    expect(m.slices[0].libraries[0].name).toBe("/usr/lib/libSystem.B.dylib");
    expect(m.slices[0].signature).toBeUndefined();
  });
});

describe("DER / X.509", () => {
  const pem = readFileSync(join(__dirname, "__fixtures__/isrg-root-x1.pem"), "utf8");

  it("parses a certificate's identity and validity", () => {
    const [cert] = certificatesFromPem(pem);
    expect(cert.subject.cn).toBe("ISRG Root X1");
    expect(cert.subject.o).toBe("Internet Security Research Group");
    expect(cert.serial).toBe("8210cfb0d240e3594463e0bb63828b00");
    expect(cert.notBefore).toBe("2015-06-04T11:04:38.000Z");
    expect(cert.notAfter).toBe("2035-06-04T11:04:38.000Z");
    expect(cert.publicKey).toMatchObject({ algorithm: "RSA", bits: 4096 });
    expect(cert.selfIssued).toBe(true);
    expect(cert.isCA).toBe(true);
    expect(createHash("sha256").update(cert.der).digest("hex")).toBe("96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6");
  });

  it("rejects malformed lengths", () => {
    expect(() => parseDer(Uint8Array.from([0x30, 0x85, 1, 2, 3, 4, 5]))).toThrow(ParseError);
    expect(() => parseDer(Uint8Array.from([0x30, 0x10, 0x02, 0x01]))).toThrow(ParseError);
  });
});
