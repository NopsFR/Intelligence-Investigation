import { extractIndicators } from "@/lib/observables/extract";
import type { ObservableType } from "@/lib/core/types";

export interface ExtractedString {
  offset: number;
  encoding: "ascii" | "utf16le";
  value: string;
  tags: StringTag[];
}

export type StringTag = "url" | "ip" | "domain" | "email" | "path" | "registry" | "base64" | "command" | "api" | "user-agent" | "crypto" | "pdb";

const TAG_RULES: [StringTag, RegExp][] = [
  ["url", /\b(https?|ftp):\/\/[^\s"'<>]{4,}/i],
  ["ip", /\b(?:\d{1,3}\.){3}\d{1,3}\b/],
  ["email", /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/],
  ["registry", /\b(HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE\\(Microsoft|Classes|Policies))\\/i],
  ["pdb", /\.pdb$/i],
  ["path", /^([A-Za-z]:\\|\\\\|%\w+%\\|\/(etc|tmp|var|usr|bin|dev|proc|home)\/)/],
  ["command", /\b(cmd(\.exe)?\s+\/c|powershell(\.exe)?\s|-enc(odedcommand)?\s|wget\s|curl\s|chmod\s+\+x|bash\s+-c|schtasks|reg\s+add|vssadmin|bcdedit|wevtutil)\b/i],
  ["user-agent", /^Mozilla\/\d\.\d \(/],
  ["crypto", /(-----BEGIN [A-Z ]+-----|\b(bitcoin|monero|wallet)\b)/i],
  ["base64", /^[A-Za-z0-9+/]{40,}={0,2}$/],
];

function tagsFor(value: string): StringTag[] {
  const tags: StringTag[] = [];
  for (const [tag, re] of TAG_RULES) if (re.test(value)) tags.push(tag);
  if (!tags.includes("url") && /^[a-z0-9-]+(\.[a-z0-9-]+)+\.(com|net|org|ru|cn|io|xyz|top|info|biz|co|me|tk|onion)$/i.test(value)) tags.push("domain");
  return tags;
}

/**
 * Printable ASCII and UTF-16LE runs, like `strings -a` plus `strings -el`.
 * Bounded so pathological inputs cannot exhaust memory.
 */
export function extractStrings(bytes: Uint8Array, minLength = 5, limit = 20_000): ExtractedString[] {
  const out: ExtractedString[] = [];
  const isPrintable = (c: number) => (c >= 0x20 && c < 0x7f) || c === 0x09;

  let start = -1;
  for (let i = 0; i <= bytes.length; i++) {
    const c = i < bytes.length ? bytes[i] : 0;
    if (isPrintable(c)) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if (i - start >= minLength) {
        let value = "";
        for (let j = start; j < Math.min(i, start + 1024); j++) value += String.fromCharCode(bytes[j]);
        out.push({ offset: start, encoding: "ascii", value, tags: tagsFor(value) });
        if (out.length >= limit) return out;
      }
      start = -1;
    }
  }

  for (const phase of [0, 1]) {
    start = -1;
    for (let i = phase; i + 1 <= bytes.length; i += 2) {
      const ok = i + 1 < bytes.length && isPrintable(bytes[i]) && bytes[i + 1] === 0;
      if (ok) {
        if (start < 0) start = i;
      } else if (start >= 0) {
        const chars = (i - start) / 2;
        if (chars >= minLength) {
          let value = "";
          for (let j = start; j < Math.min(i, start + 2048); j += 2) value += String.fromCharCode(bytes[j]);
          out.push({ offset: start, encoding: "utf16le", value, tags: tagsFor(value) });
          if (out.length >= limit) return out;
        }
        start = -1;
      }
    }
  }
  return out.sort((a, b) => a.offset - b.offset);
}

/** Investigable indicators found in strings (validated by the same detector as search). */
export function indicatorsFromStrings(strings: ExtractedString[]): { value: string; type: ObservableType; occurrences: number; offsets: number[] }[] {
  const byKey = new Map<string, { value: string; type: ObservableType; occurrences: number; offsets: number[] }>();
  for (const s of strings) {
    if (!s.tags.some((t) => t === "url" || t === "ip" || t === "domain" || t === "email")) continue;
    for (const ind of extractIndicators(s.value, 20)) {
      const key = `${ind.type}:${ind.value}`;
      const existing = byKey.get(key);
      if (existing) {
        existing.occurrences++;
        if (existing.offsets.length < 10) existing.offsets.push(s.offset);
      } else byKey.set(key, { value: ind.value, type: ind.type, occurrences: 1, offsets: [s.offset] });
    }
  }
  return [...byKey.values()];
}
