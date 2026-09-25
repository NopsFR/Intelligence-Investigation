import type { Fact, FactFormat, FactValue, TimelineEvent } from "@/lib/core/types";

/** Builds a fact, dropping empty values so views never show blank rows. */
export function fact(key: string, label: string, value: FactValue | undefined, format?: FactFormat, primary?: boolean): Fact | null {
  if (value === undefined || value === null || value === "") return null;
  if (Array.isArray(value) && value.length === 0) return null;
  if (typeof value === "number" && !Number.isFinite(value)) return null;
  return { key, label, value, ...(format ? { format } : {}), ...(primary ? { primary } : {}) };
}

export function facts(...items: (Fact | null | undefined | false)[]): Fact[] {
  return items.filter((f): f is Fact => Boolean(f));
}

/**
 * Normalises the many date formats providers emit ("2022-06-04 21:24:53",
 * "2021-07-12 12:52:32 UTC", epoch seconds, ISO) to ISO-8601, or undefined.
 */
export function toIso(input: unknown): string | undefined {
  if (input === null || input === undefined || input === "") return undefined;
  if (typeof input === "number") {
    const ms = input > 1e12 ? input : input * 1000;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
  }
  if (typeof input !== "string") return undefined;
  let s = input.trim().replace(/\s+UTC$/i, "Z");
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?(\.\d+)?Z?$/.test(s)) s = s.replace(" ", "T");
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?$/.test(s)) s += "Z";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export function event(at: unknown, label: string, detail?: string): TimelineEvent | null {
  const iso = toIso(at);
  return iso ? { at: iso, label, ...(detail ? { detail } : {}) } : null;
}

export function events(...items: (TimelineEvent | null | undefined)[]): TimelineEvent[] {
  return items.filter((e): e is TimelineEvent => Boolean(e));
}

export function uniq<T>(values: (T | null | undefined)[]): T[] {
  return [...new Set(values.filter((v): v is T => v !== null && v !== undefined && v !== ""))];
}

export function plural(n: number, word: string, pluralWord = `${word}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? word : pluralWord}`;
}

export function daysBetween(fromIso: string, to = Date.now()): number {
  return Math.floor((to - new Date(fromIso).getTime()) / 86_400_000);
}
