import type { ObservableType } from "./observable";
import type { Finding } from "./finding";
import type { ProviderOutcome } from "./provider";

export type InvestigationStatus = "PENDING" | "RUNNING" | "COMPLETE" | "PARTIAL" | "FAILED";
export type InvestigationMode = "QUICK" | "DEEP";

export interface RelationshipRecord {
  id: string;
  sourceNode: string;
  targetNode: string;
  relationType: string;
  sourceProvider: string;
  evidence: string;
  observedAt: string;
}

export interface Investigation {
  id: string;
  createdAt: string;
  updatedAt: string;
  observable: string;
  observableType: ObservableType;
  normalizedObservable: string;
  mode: InvestigationMode;
  status: InvestigationStatus;
  summary: string;
  providerResults: ProviderOutcome[];
  findings: Finding[];
  relationships: RelationshipRecord[];
}
