// Chained decoder: each step detects candidate encodings for the current
// text and can apply one, feeding its output back in as the next input. The
// detector never guesses silently — every candidate names what matched and
// why, and the user picks which one to apply.

export interface DecodeCandidate {
  id: string;
  label: string;
  confidence: "high" | "medium" | "low";
  apply: (input: string) => string;
}

const PRINTABLE_RATIO_THRESHOLD = 0.85;

function printableRatio(s: string): number {
  if (!s.length) return 0;
  let printable = 0;
  for (const c of s) {
    const code = c.codePointAt(0)!;
    if ((code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d || code > 0xa0) printable++;
  }
  return printable / s.length;
}

function bytesToLatin1(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function tryUtf8(bytes: Uint8Array): string | null {
  try {
    const s = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return s;
  } catch {
    return null;
  }
}

function decodeBase64(input: string): Uint8Array {
  const cleaned = input.trim().replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(cleaned), (c) => c.charCodeAt(0));
}

function rot(s: string, n: number): string {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + n + 26) % 26) + base);
  });
}

/** Every candidate transform that plausibly applies to the current text. */
export function detectCandidates(input: string): DecodeCandidate[] {
  const t = input.trim();
  const out: DecodeCandidate[] = [];
  if (!t) return out;

  // Base64 / Base64URL
  if (t.length >= 4 && t.length % 4 !== 1 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(t.replace(/\s+/g, ""))) {
    try {
      const bytes = decodeBase64(t.replace(/\s+/g, ""));
      const utf8 = tryUtf8(bytes);
      const text = utf8 ?? bytesToLatin1(bytes);
      const ratio = printableRatio(text);
      out.push({ id: "base64", label: `Base64 → ${utf8 ? "UTF-8" : "bytes"} (${bytes.length} bytes)`, confidence: ratio > PRINTABLE_RATIO_THRESHOLD ? "high" : "low", apply: () => text });
    } catch {
      // not valid base64 despite the shape
    }
  }

  // Hex
  const hexBody = t.replace(/^0x/i, "").replace(/\s+/g, "");
  if (hexBody.length >= 2 && hexBody.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hexBody)) {
    const bytes = Uint8Array.from(hexBody.match(/../g)!.map((h) => parseInt(h, 16)));
    const utf8 = tryUtf8(bytes);
    const text = utf8 ?? bytesToLatin1(bytes);
    out.push({ id: "hex", label: `Hex → ${utf8 ? "UTF-8" : "bytes"} (${bytes.length} bytes)`, confidence: printableRatio(text) > PRINTABLE_RATIO_THRESHOLD ? "high" : "low", apply: () => text });
  }

  // Binary (space or contiguous 8-bit groups)
  const binBody = t.replace(/\s+/g, "");
  if (binBody.length >= 8 && binBody.length % 8 === 0 && /^[01]+$/.test(binBody)) {
    const bytes = new Uint8Array(binBody.length / 8);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(binBody.slice(i * 8, i * 8 + 8), 2);
    const utf8 = tryUtf8(bytes);
    const text = utf8 ?? bytesToLatin1(bytes);
    out.push({ id: "binary", label: `Binary → ${utf8 ? "UTF-8" : "bytes"} (${bytes.length} bytes)`, confidence: printableRatio(text) > PRINTABLE_RATIO_THRESHOLD ? "high" : "low", apply: () => text });
  }

  // URL percent-encoding
  if (/%[0-9a-fA-F]{2}/.test(t)) {
    try {
      const decoded = decodeURIComponent(t);
      if (decoded !== t) out.push({ id: "url", label: "URL-decode (%XX)", confidence: "high", apply: () => decoded });
    } catch {
      // malformed sequence
    }
  }

  // HTML entities
  if (/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(t)) {
    const named: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
    const decoded = t.replace(/&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, code) => {
      if (code[0] === "#") return String.fromCodePoint(code[1] === "x" || code[1] === "X" ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10));
      return named[code.toLowerCase()] ?? m;
    });
    if (decoded !== t) out.push({ id: "html", label: "HTML entity decode", confidence: "high", apply: () => decoded });
  }

  // Unicode escapes \uXXXX
  if (/\\u[0-9a-fA-F]{4}/.test(t)) {
    const decoded = t.replace(/\\u([0-9a-fA-F]{4})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)));
    out.push({ id: "unicode-escape", label: "\\uXXXX unescape", confidence: "high", apply: () => decoded });
  }

  // Quoted-printable
  if (/=[0-9A-F]{2}/.test(t) && /=\r?\n/.test(t + "\n")) {
    const decoded = t.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)));
    out.push({ id: "quoted-printable", label: "Quoted-printable decode", confidence: "medium", apply: () => decoded });
  }

  // ROT13 / ROT47 — always offered (reversible, no reliable self-detection), low confidence
  out.push({ id: "rot13", label: "ROT13", confidence: "low", apply: () => rot(t, 13) });

  // Reverse
  out.push({ id: "reverse", label: "Reverse string", confidence: "low", apply: () => [...t].reverse().join("") });

  // Gzip / zlib magic (cannot decompress without a library; report detection honestly)
  if (t.length >= 4 && /^(1f8b|789c|78da|7801)/i.test(hexLead(t))) {
    out.push({ id: "gzip-detected", label: "Looks like gzip/zlib-compressed bytes (not decompressed here — inflate is not implemented)", confidence: "medium", apply: (x) => x });
  }

  // JWT
  if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(t)) {
    out.push({ id: "jwt", label: "JWT payload → JSON", confidence: "high", apply: () => {
      try {
        const part = t.split(".")[1];
        const bytes = decodeBase64(part.padEnd(part.length + ((4 - (part.length % 4)) % 4), "="));
        return JSON.stringify(JSON.parse(tryUtf8(bytes) ?? bytesToLatin1(bytes)), null, 2);
      } catch {
        return t;
      }
    } });
  }

  return out;
}

function hexLead(t: string): string {
  // If the text is itself hex-looking, show its leading bytes for magic detection.
  const body = t.replace(/\s+/g, "");
  if (/^[0-9a-fA-F]+$/.test(body)) return body.slice(0, 8);
  return Array.from(t.slice(0, 4)).map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
}

export interface DecodeStep {
  input: string;
  candidateId: string;
  candidateLabel: string;
  output: string;
}
