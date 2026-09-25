import type {
  InvestigationMode,
  NormalizedResult,
  ObservableType,
  ProviderCategory,
  ProviderOutcome,
} from "@/lib/core/types";
import type { ProviderRequestOptions, ProviderResponse } from "@/lib/net/provider-fetch";
import type { z } from "zod";

export type AuthRequirement =
  | { type: "none" }
  | { type: "required"; env: readonly string[]; header: string; signup: string }
  | { type: "optional"; env: readonly string[]; header: string; signup: string; benefit: string };

export type ProviderKind = "external" | "native" | "derived";

export interface ProviderRunContext {
  observable: string;
  type: ObservableType;
  mode: InvestigationMode;
  signal: AbortSignal;
  apiKey?: string;
  /** Outcomes of the tasks listed in `dependsOn`. */
  dependencies: Map<string, ProviderOutcome>;
  /** Metadata for another provider (derived analysers use it to reason about sources). */
  describe(id: string): Pick<ProviderDefinition, "id" | "name" | "vendor" | "category" | "kind"> | undefined;
  /** JSON request with schema validation; records diagnostics. */
  json<T>(url: string, schema: z.ZodType<T>, options?: ProviderRequestOptions): Promise<{ data: T; response: ProviderResponse }>;
  /** Raw request; records diagnostics. */
  request(url: string, options?: ProviderRequestOptions): Promise<ProviderResponse>;
  /** Validates a raw response body against a schema; records diagnostics. */
  parse<T>(response: ProviderResponse, schema: z.ZodType<T>): T;
  note(message: string): void;
}

export interface ProviderRunResult extends NormalizedResult {
  /** The source answered but holds nothing for this observable. */
  empty?: boolean;
  /** Some sub-queries failed; the result is still usable. */
  partial?: boolean;
  raw?: unknown;
}

export interface QuotaSpec {
  limit: number;
  windowSeconds: number;
  label: string;
}

export interface ProviderDefinition {
  id: string;
  /** Short provenance code shown next to evidence (e.g. "VT", "RDAP"). */
  code: string;
  name: string;
  vendor: string;
  category: ProviderCategory;
  kind: ProviderKind;
  /** Connects to the investigated infrastructure itself (not a third-party dataset). */
  active?: boolean;
  description: string;
  homepage: string;
  docs?: string;
  auth: AuthRequirement;
  /** Human-readable endpoint class, e.g. "REST · JSON · api.abuseipdb.com". */
  endpoint: string;
  /** Documented rate limits / fair-use terms. */
  limits?: string;
  terms?: string;
  supports: ObservableType[];
  /** Observable types for which this runs in Quick Scan (default: all supported). */
  quick?: ObservableType[] | "none";
  dependsOn?: string[];
  /** Cache lifetime for successful answers. 0 disables caching. */
  cacheTtlSeconds: number;
  timeoutMs: number;
  /** Local request budgets that keep us inside provider terms. */
  quotas?: QuotaSpec[] | ((input: { hasKey: boolean }) => QuotaSpec[]);
  /** Return a reason string to skip this provider for the given input. */
  skip?(input: { observable: string; type: ObservableType }): string | null;
  run(ctx: ProviderRunContext): Promise<ProviderRunResult>;
  /** Known observable used by "Test connection" (a real request). */
  healthCheck?: { observable: string; type: ObservableType };
}

export function definesAuth(def: ProviderDefinition): def is ProviderDefinition & { auth: Exclude<AuthRequirement, { type: "none" }> } {
  return def.auth.type !== "none";
}
