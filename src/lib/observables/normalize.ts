import type { ObservableType } from "@/types/observable";

/**
 * Normalizes an already-typed observable value for consistent storage/lookup.
 * Detection already normalizes on the way in; this is used when a value
 * arrives already typed (e.g. from the database or a provider response).
 */
export function normalizeObservable(value: string, type: ObservableType): string {
  const trimmed = value.trim();
  switch (type) {
    case "DOMAIN":
      return trimmed.toLowerCase().replace(/\.$/, "");
    case "IPV6":
      return trimmed.toLowerCase();
    case "MD5":
    case "SHA1":
    case "SHA256":
      return trimmed.toLowerCase();
    case "CVE":
      return trimmed.toUpperCase();
    case "ASN": {
      const digits = trimmed.replace(/[^\d]/g, "");
      return `AS${digits}`;
    }
    case "URL":
      try {
        return new URL(trimmed).toString();
      } catch {
        return trimmed;
      }
    default:
      return trimmed;
  }
}

/** Normalizes certificate-transparency style names (crt.sh) for dedupe. */
export function normalizeCertName(name: string): string | null {
  const cleaned = name.trim().toLowerCase().replace(/\*\./, "");
  if (!cleaned || cleaned.includes(" ") || cleaned.includes("@")) return null;
  if (!/^[a-z0-9.-]+$/.test(cleaned)) return null;
  return cleaned;
}
