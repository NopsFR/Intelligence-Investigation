"use client";

import { createContext, useContext } from "react";
import type { InvestigationRecord } from "@/lib/core/types";

export interface WorkspaceContextValue {
  inv: InvestigationRecord;
  openSource: (provider: string, focus?: "raw") => void;
  openFinding: (id: string) => void;
  goTab: (tab: string) => void;
}

export const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export function useWorkspace(): WorkspaceContextValue {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) throw new Error("useWorkspace outside investigation workspace");
  return ctx;
}
