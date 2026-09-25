import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { detectCandidates } from "./decoder";
import { aesDecrypt, aesEncrypt, fromBase64, fromHex, hashText, hex, hmac, rsaDecrypt, rsaEncrypt, rsaGenerateKeyPair, rsaSign, rsaVerify, toBase64, xorBruteForce, xorBytes } from "./crypto";

describe("decoder detection", () => {
  it("detects base64 with UTF-8 output", () => {
    const cands = detectCandidates(btoa("hello world"));
    const b64 = cands.find((c) => c.id === "base64");
    expect(b64?.apply("")).toBe("hello world");
    expect(b64?.confidence).toBe("high");
  });

  it("detects hex", () => {
    const cands = detectCandidates("68656c6c6f");
    expect(cands.find((c) => c.id === "hex")?.apply("")).toBe("hello");
  });

  it("detects binary", () => {
    const cands = detectCandidates("01001000 01001001");
    expect(cands.find((c) => c.id === "binary")?.apply("")).toBe("HI");
  });

  it("detects URL percent-encoding", () => {
    const cands = detectCandidates("hello%20world%21");
    expect(cands.find((c) => c.id === "url")?.apply("")).toBe("hello world!");
  });

  it("detects HTML entities", () => {
    const cands = detectCandidates("A &amp; B &lt;3");
    expect(cands.find((c) => c.id === "html")?.apply("")).toBe("A & B <3");
  });

  it("detects unicode escapes", () => {
    const cands = detectCandidates("\\u0048\\u0069");
    expect(cands.find((c) => c.id === "unicode-escape")?.apply("")).toBe("Hi");
  });

  it("always offers ROT13 as reversible, low-confidence", () => {
    const cands = detectCandidates("uryyb");
    const rot13 = cands.find((c) => c.id === "rot13")!;
    expect(rot13.apply("")).toBe("hello");
    expect(rot13.confidence).toBe("low");
  });

  it("decodes a JWT payload to formatted JSON", () => {
    const payload = btoa(JSON.stringify({ sub: "1234" })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const header = btoa(JSON.stringify({ alg: "HS256" })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const cands = detectCandidates(`${header}.${payload}.sig`);
    expect(cands.find((c) => c.id === "jwt")?.apply("")).toContain('"sub": "1234"');
  });

  it("returns nothing for empty input", () => {
    expect(detectCandidates("")).toEqual([]);
  });
});

describe("crypto lab", () => {
  it("hashes text with MD5 and SHA family matching Node", async () => {
    expect(await hashText("MD5", "abc")).toBe(createHash("md5").update("abc").digest("hex"));
    expect(await hashText("SHA-256", "abc")).toBe(createHash("sha256").update("abc").digest("hex"));
  });

  it("computes HMAC matching Node", async () => {
    expect(await hmac("SHA-256", "key", "message")).toBe(createHmac("sha256", "key").update("message").digest("hex"));
  });

  it("XORs bytes and is its own inverse", () => {
    const data = new TextEncoder().encode("hello world");
    const key = new TextEncoder().encode("k3y");
    const enc = xorBytes(data, key);
    const dec = xorBytes(enc, key);
    expect(new TextDecoder().decode(dec)).toBe("hello world");
  });

  it("single-byte XOR brute force ranks the correct key highest", () => {
    const plain = new TextEncoder().encode("The quick brown fox jumps over the lazy dog");
    const enc = xorBytes(plain, Uint8Array.of(0x42));
    const results = xorBruteForce(enc, 5);
    expect(results[0].key).toBe(0x42);
    expect(results[0].text).toContain("quick brown fox");
  });

  it("hex and base64 round-trip", () => {
    const bytes = Uint8Array.of(1, 2, 3, 255, 0);
    expect(fromHex(hex(bytes))).toEqual(bytes);
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });

  it("rejects malformed hex", () => {
    expect(() => fromHex("abc")).toThrow();
    expect(() => fromHex("zz")).toThrow();
  });

  it("AES-GCM round-trips and detects tampering", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode("top secret message");
    const ct = await aesEncrypt("AES-GCM", key, iv, plaintext);
    const pt = await aesDecrypt("AES-GCM", key, iv, ct);
    expect(new TextDecoder().decode(pt)).toBe("top secret message");
    const tampered = new Uint8Array(ct);
    tampered[0] ^= 0xff;
    await expect(aesDecrypt("AES-GCM", key, iv, tampered)).rejects.toThrow();
  });

  it("AES-CBC round-trips", async () => {
    const key = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const plaintext = new TextEncoder().encode("block cipher test message");
    const ct = await aesEncrypt("AES-CBC", key, iv, plaintext);
    const pt = await aesDecrypt("AES-CBC", key, iv, ct);
    expect(new TextDecoder().decode(pt)).toBe("block cipher test message");
  });

  it("RSA-OAEP encrypts and decrypts", async () => {
    const kp = await rsaGenerateKeyPair(2048, "encrypt");
    expect(kp.publicKeyPem).toContain("BEGIN PUBLIC KEY");
    const plaintext = new TextEncoder().encode("rsa test");
    const ct = await rsaEncrypt(kp.publicKey, plaintext);
    const pt = await rsaDecrypt(kp.privateKey, ct);
    expect(new TextDecoder().decode(pt)).toBe("rsa test");
  }, 15000);

  it("RSA-PSS signs and verifies, and rejects a tampered message", async () => {
    const kp = await rsaGenerateKeyPair(2048, "sign");
    const message = new TextEncoder().encode("sign me");
    const sig = await rsaSign(kp.privateKey, message);
    expect(await rsaVerify(kp.publicKey, message, sig)).toBe(true);
    expect(await rsaVerify(kp.publicKey, new TextEncoder().encode("sign me!"), sig)).toBe(false);
  }, 15000);
});
