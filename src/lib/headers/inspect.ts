import { safeFetch } from "@/lib/security/safeFetch";
import type { NormalizedFinding } from "@/types/provider";

const HEADERS_TO_CHECK = [
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
] as const;

export type SecurityHeaderName = (typeof HEADERS_TO_CHECK)[number];

export interface SecurityHeaderResult {
  reachable: boolean;
  finalUrl?: string;
  status?: number;
  headers: Record<SecurityHeaderName, string | null>;
  error?: string;
}

const HEADER_LABELS: Record<SecurityHeaderName, string> = {
  "content-security-policy": "Content-Security-Policy",
  "strict-transport-security": "Strict-Transport-Security",
  "x-content-type-options": "X-Content-Type-Options",
  "x-frame-options": "X-Frame-Options",
  "referrer-policy": "Referrer-Policy",
  "permissions-policy": "Permissions-Policy",
  "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
  "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
};

const OPTIONAL_HEADERS: SecurityHeaderName[] = [
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

export async function inspectSecurityHeaders(targetUrl: string): Promise<SecurityHeaderResult> {
  try {
    const response = await safeFetch(targetUrl, { method: "GET", timeoutMs: 8000 });
    const headers = {} as Record<SecurityHeaderName, string | null>;
    for (const h of HEADERS_TO_CHECK) {
      headers[h] = response.headers.get(h);
    }
    return { reachable: true, status: response.status, headers };
  } catch (err) {
    const headers = {} as Record<SecurityHeaderName, string | null>;
    for (const h of HEADERS_TO_CHECK) headers[h] = null;
    return {
      reachable: false,
      headers,
      error: err instanceof Error ? err.message : "Unable to retrieve headers",
    };
  }
}

export function findingsForHeaders(hostname: string, result: SecurityHeaderResult): NormalizedFinding[] {
  if (!result.reachable) return [];

  const findings: NormalizedFinding[] = [];
  for (const h of HEADERS_TO_CHECK) {
    if (result.headers[h]) continue;
    const optional = OPTIONAL_HEADERS.includes(h);
    findings.push({
      severity: optional ? "INFO" : "LOW",
      category: "headers",
      title: `${HEADER_LABELS[h]} header absent`,
      description: `The response from ${hostname} did not include a ${HEADER_LABELS[h]} header.`,
      evidence: `HTTP response headers did not contain "${h}".`,
    });
  }
  return findings;
}
