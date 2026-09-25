import type { ObservableType } from "@/lib/core/types";
import { detectObservable } from "./detect";
import { refang } from "./fang";

export interface ExtractedIndicator {
  value: string;
  type: ObservableType;
  occurrences: number;
}

const PATTERNS: RegExp[] = [
  /\bh(?:tt|xx|XX)ps?:\/\/[^\s"'<>()\]]+/gi,
  /\bCVE-\d{4}-\d{4,}\b/gi,
  /\b(?:[a-f0-9]{2}:){31}[a-f0-9]{2}\b/gi,
  /\b[a-f0-9]{64}\b/gi,
  /\b[a-f0-9]{40}\b/gi,
  /\b[a-f0-9]{32}\b/gi,
  /\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}\b/gi,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{0,4}\b/gi,
  /\bAS\d{1,10}\b/g,
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b/gi,
];

/**
 * Extracts investigable indicators from unstructured text (reports, emails,
 * chat). Defanged indicators are refanged first. Every candidate is validated
 * by the same detector used for search, so nothing un-investigable is returned.
 */
export function extractIndicators(text: string, limit = 500): ExtractedIndicator[] {
  const source = refang(text.slice(0, 200_000))
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/hxxp/gi, "http");

  const found = new Map<string, ExtractedIndicator>();
  const consumed: [number, number][] = [];
  const overlaps = (start: number, end: number) => consumed.some(([s, e]) => start < e && end > s);

  for (const pattern of PATTERNS) {
    for (const match of source.matchAll(pattern)) {
      const start = match.index ?? 0;
      const end = start + match[0].length;
      if (overlaps(start, end)) continue;
      const candidate = match[0].replace(/[.,;:]+$/, "");
      const detected = detectObservable(candidate);
      if (!detected) continue;
      consumed.push([start, end]);
      const key = `${detected.type}:${detected.normalized}`;
      const existing = found.get(key);
      if (existing) existing.occurrences += 1;
      else found.set(key, { value: detected.normalized, type: detected.type, occurrences: 1 });
      if (found.size >= limit) return [...found.values()];
    }
  }
  return [...found.values()];
}
