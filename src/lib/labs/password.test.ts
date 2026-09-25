import { describe, expect, it } from "vitest";
import { analyzePassword, generatePassphrase, generatePassword, passphraseEntropyBits, PASSPHRASE_WORDS } from "./password";

describe("analyzePassword", () => {
  it("flags a common password as very weak", () => {
    const r = analyzePassword("password");
    expect(r.tier).toBe("very-weak");
    expect(r.patterns.some((p) => p.id === "common")).toBe(true);
  });

  it("flags a common word with a numeric suffix (e.g. password123)", () => {
    const r = analyzePassword("password123");
    expect(r.patterns.some((p) => p.id === "common-stem")).toBe(true);
  });

  it("flags short length", () => {
    const r = analyzePassword("Ab1!");
    expect(r.patterns.some((p) => p.id === "short")).toBe(true);
  });

  it("flags sequential runs", () => {
    const r = analyzePassword("myabcd1234pass");
    expect(r.patterns.some((p) => p.id === "sequential")).toBe(true);
  });

  it("flags keyboard-adjacent runs", () => {
    const r = analyzePassword("xqwertyx1");
    expect(r.patterns.some((p) => p.id === "keyboard")).toBe(true);
  });

  it("flags long repeated-character runs", () => {
    const r = analyzePassword("aaaaaa1B");
    expect(r.patterns.some((p) => p.id === "repeat")).toBe(true);
  });

  it("rates a long random-looking password highly", () => {
    const r = analyzePassword("qX7!kR2#pL9$wZ4&");
    expect(r.tier === "strong" || r.tier === "very-strong").toBe(true);
    expect(r.patterns.length).toBe(0);
  });

  it("computes a charset pool size covering all classes used", () => {
    const r = analyzePassword("Ab1!");
    expect(r.charset.lower).toBe(true);
    expect(r.charset.upper).toBe(true);
    expect(r.charset.digit).toBe(true);
    expect(r.charset.symbol).toBe(true);
    expect(r.charset.poolSize).toBe(26 + 26 + 10 + 33);
  });

  it("handles an empty password without throwing", () => {
    const r = analyzePassword("");
    expect(r.length).toBe(0);
    expect(r.entropyBits).toBe(0);
    expect(r.tier).toBe("very-weak");
  });
});

describe("generatePassword", () => {
  it("respects the requested length", () => {
    expect(generatePassword({ length: 20, lower: true, upper: true, digits: true, symbols: true })).toHaveLength(20);
  });

  it("includes at least one character from every selected class", () => {
    for (let i = 0; i < 20; i++) {
      const pw = generatePassword({ length: 16, lower: true, upper: true, digits: true, symbols: true });
      expect(/[a-z]/.test(pw)).toBe(true);
      expect(/[A-Z]/.test(pw)).toBe(true);
      expect(/[0-9]/.test(pw)).toBe(true);
    }
  });

  it("throws when no character set is selected", () => {
    expect(() => generatePassword({ length: 10, lower: false, upper: false, digits: false, symbols: false })).toThrow();
  });

  it("only uses the selected character classes", () => {
    for (let i = 0; i < 10; i++) {
      const pw = generatePassword({ length: 30, lower: true, upper: false, digits: false, symbols: false });
      expect(/^[a-z]+$/.test(pw)).toBe(true);
    }
  });
});

describe("generatePassphrase", () => {
  it("produces the requested number of words from the list", () => {
    const phrase = generatePassphrase(5);
    const words = phrase.split("-");
    expect(words).toHaveLength(5);
    for (const w of words) expect(PASSPHRASE_WORDS).toContain(w);
  });

  it("computes honest entropy for the word count", () => {
    expect(passphraseEntropyBits(6)).toBeCloseTo(6 * Math.log2(PASSPHRASE_WORDS.length), 5);
  });
});
