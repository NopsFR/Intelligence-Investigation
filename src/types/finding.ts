export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  id: string;
  severity: FindingSeverity;
  category: string;
  title: string;
  description: string;
  evidence: string;
  source: string;
  observedAt: string;
  confidence?: string;
  methodology?: string;
}

export const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};
