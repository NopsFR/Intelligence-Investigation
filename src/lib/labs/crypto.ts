import { md5 } from "@/lib/analysis/hash";

// Real cryptographic primitives via WebCrypto (and the pure-JS MD5 already
// used for file hashing, since WebCrypto omits it). Every operation runs in
// the browser; no key or plaintext is sent anywhere.

const enc = new TextEncoder();

export async function hashText(algorithm: "MD5" | "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512", text: string): Promise<string> {
  const bytes = enc.encode(text);
  if (algorithm === "MD5") return md5(bytes);
  const buf = await crypto.subtle.digest(algorithm, bytes as unknown as BufferSource);
  return hex(new Uint8Array(buf));
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s: string): Uint8Array {
  const clean = s.trim().replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) throw new Error("Not valid hex (even number of hex digits required)");
  return Uint8Array.from(clean.match(/../g) ?? [], (h) => parseInt(h, 16));
}

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(s: string): Uint8Array {
  return Uint8Array.from(atob(s.trim()), (c) => c.charCodeAt(0));
}

const HMAC_ALG: Record<string, string> = { "SHA-1": "SHA-1", "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512" };

export async function hmac(algorithm: keyof typeof HMAC_ALG, keyText: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(keyText), { name: "HMAC", hash: HMAC_ALG[algorithm] }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return hex(new Uint8Array(sig));
}

export function xorBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
  if (!key.length) throw new Error("Key must not be empty");
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
  return out;
}

/** Single-byte XOR brute force, ranked by printable-ASCII ratio of the result. */
export function xorBruteForce(data: Uint8Array, top = 10): { key: number; text: string; score: number }[] {
  const results: { key: number; text: string; score: number }[] = [];
  for (let k = 0; k < 256; k++) {
    const out = xorBytes(data, Uint8Array.of(k));
    let printable = 0;
    let letters = 0;
    let spaces = 0;
    for (const b of out) {
      if ((b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13) printable++;
      if ((b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)) letters++;
      if (b === 0x20) spaces++;
    }
    let text = "";
    for (const b of out) text += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
    // Printable ratio disambiguates readable output from noise; the
    // letter/space mix then favours natural-language text over other
    // printable-but-unlikely results (e.g. all-digit or all-punctuation keys).
    const n = Math.max(1, out.length);
    const score = printable / n + (letters / n) * 0.5 + (spaces / n) * 0.25;
    results.push({ key: k, text, score });
  }
  return results.sort((a, b) => b.score - a.score).slice(0, top);
}

// ---------------------------------------------------------------- AES (WebCrypto)

export type AesMode = "AES-GCM" | "AES-CBC" | "AES-CTR";

export async function aesGenerateKey(bits: 128 | 192 | 256 = 256): Promise<Uint8Array> {
  return crypto.getRandomValues(new Uint8Array(bits / 8));
}

export async function aesEncrypt(mode: AesMode, keyBytes: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes as unknown as BufferSource, mode, false, ["encrypt"]);
  const params: AesGcmParams | AesCbcParams | AesCtrParams = mode === "AES-CTR" ? { name: "AES-CTR", counter: iv as unknown as BufferSource, length: 64 } : { name: mode, iv: iv as unknown as BufferSource };
  const buf = await crypto.subtle.encrypt(params, key, plaintext as unknown as BufferSource);
  return new Uint8Array(buf);
}

export async function aesDecrypt(mode: AesMode, keyBytes: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes as unknown as BufferSource, mode, false, ["decrypt"]);
  const params: AesGcmParams | AesCbcParams | AesCtrParams = mode === "AES-CTR" ? { name: "AES-CTR", counter: iv as unknown as BufferSource, length: 64 } : { name: mode, iv: iv as unknown as BufferSource };
  const buf = await crypto.subtle.decrypt(params, key, ciphertext as unknown as BufferSource);
  return new Uint8Array(buf);
}

export function ivLength(mode: AesMode): number {
  return mode === "AES-GCM" ? 12 : 16;
}

// ---------------------------------------------------------------- RSA (WebCrypto)

export interface RsaKeyPairExport {
  publicKeyPem: string;
  privateKeyPem: string;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

function pem(label: string, der: ArrayBuffer): string {
  const b64 = toBase64(new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export async function rsaGenerateKeyPair(modulusLength: 2048 | 3072 | 4096, usage: "encrypt" | "sign"): Promise<RsaKeyPairExport> {
  const algorithm =
    usage === "encrypt"
      ? { name: "RSA-OAEP", modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }
      : { name: "RSA-PSS", modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  const pair = await crypto.subtle.generateKey(algorithm, true, usage === "encrypt" ? ["encrypt", "decrypt"] : ["sign", "verify"]);
  const [pub, priv] = await Promise.all([crypto.subtle.exportKey("spki", pair.publicKey), crypto.subtle.exportKey("pkcs8", pair.privateKey)]);
  return { publicKeyPem: pem("PUBLIC KEY", pub), privateKeyPem: pem("PRIVATE KEY", priv), publicKey: pair.publicKey, privateKey: pair.privateKey };
}

export async function rsaEncrypt(publicKey: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, plaintext as unknown as BufferSource);
  return new Uint8Array(buf);
}

export async function rsaDecrypt(privateKey: CryptoKey, ciphertext: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, ciphertext as unknown as BufferSource);
  return new Uint8Array(buf);
}

export async function rsaSign(privateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, privateKey, message as unknown as BufferSource);
  return new Uint8Array(buf);
}

export async function rsaVerify(publicKey: CryptoKey, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, publicKey, signature as unknown as BufferSource, message as unknown as BufferSource);
}
