// Shared domain types. Safe to import from both server and client code.

export const OBSERVABLE_TYPES = [
  "IPV4",
  "IPV6",
  "DOMAIN",
  "URL",
  "EMAIL",
  "MD5",
  "SHA1",
  "SHA256",
  "CVE",
  "ASN",
  "CERT_SHA256",
] as const;
export type ObservableType = (typeof OBSERVABLE_TYPES)[number];

export const OBSERVABLE_LABELS: Record<ObservableType, string> = {
  IPV4: "IPv4 address",
  IPV6: "IPv6 address",
  DOMAIN: "Domain",
  URL: "URL",
  EMAIL: "Email address",
  MD5: "MD5 hash",
  SHA1: "SHA-1 hash",
  SHA256: "SHA-256 hash",
  CVE: "CVE identifier",
  ASN: "Autonomous system",
  CERT_SHA256: "Certificate fingerprint",
};

export const OBSERVABLE_SHORT: Record<ObservableType, string> = {
  IPV4: "IPv4",
  IPV6: "IPv6",
  DOMAIN: "Domain",
  URL: "URL",
  EMAIL: "Email",
  MD5: "MD5",
  SHA1: "SHA1",
  SHA256: "SHA256",
  CVE: "CVE",
  ASN: "ASN",
  CERT_SHA256: "Cert",
};

export type InvestigationMode = "QUICK" | "DEEP";
export type InvestigationStatus = "PENDING" | "RUNNING" | "COMPLETE" | "PARTIAL" | "FAILED";

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
  "SKIPPED",
] as const;
export type ProviderStatus = (typeof PROVIDER_STATUSES)[number];

/** Display-only lifecycle states used while an investigation is in flight. */
export type TaskState = "QUEUED" | "RUNNING" | ProviderStatus;

export const STATUS_LABELS: Record<TaskState, string> = {
  QUEUED: "Queued",
  RUNNING: "Running",
  SUCCESS: "Complete",
  PARTIAL: "Partial",
  EMPTY: "No result",
  NOT_CONFIGURED: "Not configured",
  RATE_LIMITED: "Rate limited",
  AUTH_FAILED: "Authentication failed",
  TIMEOUT: "Timeout",
  NETWORK_ERROR: "Network error",
  INVALID_RESPONSE: "Invalid provider response",
  UNAVAILABLE: "Unavailable",
  SKIPPED: "Not applicable",
};

/** Statuses meaning the provider answered (with or without data). */
export const ANSWERED_STATUSES: ReadonlySet<ProviderStatus> = new Set(["SUCCESS", "PARTIAL", "EMPTY"]);
/** Statuses that are not failures of the provider (it simply did not run). */
export const NEUTRAL_STATUSES: ReadonlySet<ProviderStatus> = new Set(["NOT_CONFIGURED", "SKIPPED"]);

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export type ProviderCategory =
  | "threat-intel"
  | "reputation"
  | "malware"
  | "vulnerability"
  | "infrastructure"
  | "dns"
  | "certificates"
  | "web"
  | "email"
  | "correlation";

export const CATEGORY_LABELS: Record<ProviderCategory, string> = {
  "threat-intel": "Threat intelligence",
  reputation: "Reputation",
  malware: "Malware intelligence",
  vulnerability: "Vulnerability intelligence",
  infrastructure: "Infrastructure",
  dns: "DNS",
  certificates: "Certificates",
  web: "Web / HTTP",
  email: "Email security",
  correlation: "Correlation",
};

export type FactFormat =
  | "text"
  | "mono"
  | "date"
  | "datetime"
  | "number"
  | "percent"
  | "bytes"
  | "list"
  | "url"
  | "bool"
  | "code";

export type FactValue = string | number | boolean | null | string[];

export interface Fact {
  key: string;
  label: string;
  value: FactValue;
  format?: FactFormat;
  /** Surfaced in the investigation overview. */
  primary?: boolean;
}

export type NodeType =
  | "ip"
  | "domain"
  | "url"
  | "email"
  | "hash"
  | "asn"
  | "prefix"
  | "certificate"
  | "malware"
  | "cve"
  | "technique"
  | "software"
  | "group"
  | "product"
  | "port"
  | "organization";

export interface NodeRef {
  type: NodeType;
  value: string;
  label?: string;
}

export interface NormalizedRelationship {
  source: NodeRef;
  target: NodeRef;
  type: string;
  evidence: string;
}

export interface Reference {
  label: string;
  url: string;
}

export interface NormalizedFinding {
  rule: string;
  severity: Severity;
  category: string;
  title: string;
  /** What was found. */
  description: string;
  /** Why it matters. */
  rationale?: string;
  /** One-line evidence statement. */
  evidence: string;
  /** Structured evidence rendered as key/value pairs. */
  evidenceData?: Record<string, FactValue>;
  /** Affected observable when it differs from the investigated one. */
  observable?: string;
  /** Only set when the source supplies a confidence value. */
  confidence?: string;
  remediation?: string;
  references?: Reference[];
}

export interface TimelineEvent {
  at: string;
  label: string;
  detail?: string;
}

export interface NormalizedResult {
  summary: string;
  /** The observable exists in this source's dataset (listing, record, sighting). */
  listed?: boolean;
  facts: Fact[];
  /** Typed payload consumed by specialised views; `kind` discriminates the shape. */
  data?: { kind: string } & Record<string, unknown>;
  findings?: NormalizedFinding[];
  relationships?: NormalizedRelationship[];
  timeline?: TimelineEvent[];
  links?: Reference[];
  tags?: string[];
}

export interface ProviderDiagnostics {
  endpoint?: string;
  requests?: number;
  validation?: "passed" | "failed" | "not-applicable";
  bytes?: number;
  note?: string;
}

export interface ProviderOutcome {
  provider: string;
  status: ProviderStatus;
  latencyMs: number;
  startedAt?: string;
  retrievedAt: string;
  cached?: boolean;
  httpStatus?: number;
  errorType?: string;
  errorMessage?: string;
  result?: NormalizedResult;
  raw?: unknown;
  diagnostics?: ProviderDiagnostics;
}

export interface PlanStep {
  id: string;
  dependsOn?: string[];
}

export interface FindingRecord extends NormalizedFinding {
  id: string;
  source: string;
  observedAt: string;
}

export interface RelationshipRecord {
  id: string;
  source: NodeRef;
  target: NodeRef;
  type: string;
  providers: string[];
  evidence: string[];
  observedAt: string;
}

export interface InvestigationRecord {
  id: string;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  durationMs?: number;
  observable: string;
  observableType: ObservableType;
  normalizedObservable: string;
  mode: InvestigationMode;
  status: InvestigationStatus;
  summary: string;
  plan: PlanStep[];
  previousId?: string;
  providerResults: ProviderOutcome[];
  findings: FindingRecord[];
  relationships: RelationshipRecord[];
}

export interface InvestigationSummary {
  id: string;
  createdAt: string;
  completedAt?: string;
  durationMs?: number;
  observable: string;
  observableType: ObservableType;
  normalizedObservable: string;
  mode: InvestigationMode;
  status: InvestigationStatus;
  summary: string;
  findingCounts: Record<Severity, number>;
  providerCounts: { total: number; answered: number; failed: number; notConfigured: number };
}

/** Client-safe provider metadata (the registry itself is server-only). */
export interface ProviderMeta {
  id: string;
  code: string;
  name: string;
  vendor: string;
  category: ProviderCategory;
  kind: "external" | "native" | "derived";
  active: boolean;
  auth: "none" | "required" | "optional";
  homepage: string;
  supports: ObservableType[];
}
