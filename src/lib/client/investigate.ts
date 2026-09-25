"use client";

import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import type { InvestigationMode, ObservableType } from "@/lib/core/types";
import { useToast } from "@/components/ui/overlays";
import { ApiClientError, api } from "./api";

export interface StartResponse {
  id: string;
  reused: boolean;
  detected: { type: ObservableType; normalized: string; notes: string[] };
}

/** Starts an investigation and navigates to its workspace. */
export function useInvestigate() {
  const router = useRouter();
  const toast = useToast();
  const [pending, setPending] = useState(false);

  const start = useCallback(
    async (observable: string, mode: InvestigationMode, options: { type?: ObservableType; fresh?: boolean } = {}) => {
      if (!observable.trim() || pending) return null;
      setPending(true);
      try {
        const res = await api<StartResponse>("/api/investigations", { method: "POST", json: { observable, mode, ...options } });
        if (res.reused) toast({ kind: "info", title: "Already running", body: "An identical investigation is in progress — showing it instead of starting a duplicate." });
        router.push(`/investigations/${res.id}`);
        return res;
      } catch (err) {
        const e = err as ApiClientError;
        toast({ kind: "error", title: e.code === "operator-required" ? "Operator session required" : e.code === "unrecognised-observable" ? "Not a recognised observable" : "Could not start the investigation", body: e.message });
        return null;
      } finally {
        setPending(false);
      }
    },
    [pending, router, toast]
  );

  return { start, pending };
}
