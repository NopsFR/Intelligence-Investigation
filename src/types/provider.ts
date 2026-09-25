import type { ObservableType } from "./observable";

export const PROVIDER_STATUSES = [
  "SUCCESS",
  "PARTIAL",
  "EMPTY",
  "NOT_CONFIGURED",
  "RATE_LIMITED",
  "AUTH_FAILED",
  "TIMEOUT",
  "NETWORK_ERROR",
  "INVALID_RESPONSE",
  "UNAVAILABLE",
] as const;

export type ProviderStatus = (typeof PROVIDER_STATUSES)[number];

export const PROVIDER_STATUS_LABELS: Record<ProviderStatus, string> = {
  SUCCESS: "Connected",
  PARTIAL: "Partial",
  EMPTY: "No result",
  NOT_CONFIGURED: "Not configured",
  RATE_LIMITED: "Rate limited",
  AUTH_FAILED: "Authentication failed",
  TIMEOUT: "Timeout",
  NETWORK_ERROR: "Network error",
  INVALID_RESPONSE: "Invalid provider response",
  UNAVAILABLE: "Unavailable",
};

export type ProviderAvailability = "no-key" | "free-registration" | "quota-limited";

export interface ProviderMeta {
  id: string;
  name: string;
  description: string;
  availability: ProviderAvailability;
  homepage: string;
  supports: ObservableType[];
  requiresEnv?: string[];
}

/** A single normalized relationship edge discovered by a provider. */
export interface NormalizedRelationship {
  sourceNode: string;
  targetNode: string;
  relationType: string;
  evidence: string;
}

/** A single normalized finding candidate emitted by a provider. */
export interface NormalizedFinding {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  title: string;
  description: string;
  evidence: string;
  confidence?: string;
}

/** Provider-agnostic normalized shape the UI actually renders. */
export interface NormalizedResult {
  summary: string;
  fields: Record<string, unknown>;
  relationships?: NormalizedRelationship[];
  findings?: NormalizedFinding[];
  links?: { label: string; url: string }[];
}

export interface ProviderOutcome {
  provider: string;
  status: ProviderStatus;
  latencyMs: number;
  retrievedAt: string;
  errorType?: string;
  errorMessage?: string;
  normalized?: NormalizedResult;
  raw?: unknown;
}

export interface ProviderContext {
  observable: string;
  type: ObservableType;
  signal: AbortSignal;
}

export interface Provider {
  meta: ProviderMeta;
  isConfigured(): boolean;
  supports(type: ObservableType): boolean;
  investigate(ctx: ProviderContext): Promise<ProviderOutcome>;
  /** Lightweight connectivity/auth check used by the API Observatory. */
  healthCheck(): Promise<ProviderOutcome>;
}
