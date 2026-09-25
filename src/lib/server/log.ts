import "server-only";

const SECRET_KEY = /(key|token|secret|password|authorization|cookie|session|dsn|database_url)/i;
const SECRET_VALUE = /(postgres(ql)?:\/\/[^\s]+|[A-Za-z0-9_-]{32,}|Bearer\s+\S+)/g;

function scrub(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[depth]";
  if (typeof value === "string") return value.replace(SECRET_VALUE, "[redacted]").slice(0, 2000);
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => scrub(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SECRET_KEY.test(k) ? "[redacted]" : scrub(v, depth + 1)]));
  }
  return value;
}

/** Structured single-line logs. Values that look like credentials or connection strings are redacted. */
export function log(level: "info" | "warn" | "error", message: string, meta?: Record<string, unknown>) {
  const line = JSON.stringify({ level, message, ...(meta ? (scrub(meta) as Record<string, unknown>) : {}), at: new Date().toISOString() });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.info(line);
}
