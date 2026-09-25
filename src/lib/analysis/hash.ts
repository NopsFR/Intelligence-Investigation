// File hashing. SHA family via WebCrypto (browser and Node); MD5 implemented
// here because WebCrypto deliberately omits it — it is still the identifier
// most threat-intelligence sources index by.

const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

/** RFC 1321 MD5. Streaming over 64-byte blocks; no copy of the whole input. */
export function md5(input: Uint8Array): string {
  let a0 = 0x67452301,
    b0 = 0xefcdab89,
    c0 = 0x98badcfe,
    d0 = 0x10325476;
  const bitLen = BigInt(input.length) * BigInt(8);
  const tailLen = ((input.length % 64) < 56 ? 64 : 128) - (input.length % 64);
  const tail = new Uint8Array(tailLen);
  tail[0] = 0x80;
  for (let i = 0; i < 8; i++) tail[tailLen - 8 + i] = Number((bitLen >> BigInt(8 * i)) & BigInt(0xff));
  const total = input.length + tailLen;
  const M = new Uint32Array(16);
  const byteAt = (i: number) => (i < input.length ? input[i] : tail[i - input.length]);
  for (let off = 0; off < total; off += 64) {
    for (let j = 0; j < 16; j++) {
      const p = off + j * 4;
      M[j] = (byteAt(p) | (byteAt(p + 1) << 8) | (byteAt(p + 2) << 16) | (byteAt(p + 3) << 24)) >>> 0;
    }
    let A = a0,
      B = b0,
      C = c0,
      D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((v, i) => {
    out[i * 4] = v & 0xff;
    out[i * 4 + 1] = (v >>> 8) & 0xff;
    out[i * 4 + 2] = (v >>> 16) & 0xff;
    out[i * 4 + 3] = (v >>> 24) & 0xff;
  });
  return Array.from(out, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function digest(algorithm: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512", input: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest(algorithm, input as unknown as BufferSource);
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
}

export async function fileHashes(bytes: Uint8Array): Promise<FileHashes> {
  const [sha1, sha256, sha512] = await Promise.all([digest("SHA-1", bytes), digest("SHA-256", bytes), digest("SHA-512", bytes)]);
  return { md5: md5(bytes), sha1, sha256, sha512 };
}
