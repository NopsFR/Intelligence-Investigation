import { formatDistanceToNowStrict } from "date-fns";

export type TimeZonePref = "utc" | "local";

export function relative(iso: string | undefined | null, now = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  if (Math.abs(now - t) < 45_000) return "just now";
  return formatDistanceToNowStrict(t, { addSuffix: true });
}

const pad = (n: number) => String(n).padStart(2, "0");

export function dateTime(iso: string | undefined | null, tz: TimeZonePref = "utc", withSeconds = false): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  if (tz === "utc") {
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${withSeconds ? `:${pad(d.getUTCSeconds())}` : ""} UTC`;
  }
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}${withSeconds ? `:${pad(d.getSeconds())}` : ""}`;
}

export function dateOnly(iso: string | undefined | null, tz: TimeZonePref = "utc"): string {
  return dateTime(iso, tz).slice(0, 10);
}

export function duration(ms: number | undefined | null): string {
  if (ms === undefined || ms === null) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

export function num(n: number | undefined | null): string {
  return n === undefined || n === null ? "—" : n.toLocaleString("en-GB");
}

/** Keeps both ends of long identifiers (hashes, URLs) readable. */
export function middle(value: string, max = 42): string {
  if (value.length <= max) return value;
  const keep = Math.floor((max - 1) / 2);
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}
