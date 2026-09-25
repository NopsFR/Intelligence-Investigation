"use client";

import { useEffect, useState } from "react";
import type { ObservableType } from "@/lib/core/types";

export interface Detection {
  type: ObservableType | null;
  label?: string;
  normalized?: string;
  alternatives?: ObservableType[];
  notes?: string[];
}

/** Server-side detection (Public Suffix List lives on the server), debounced. */
export function useDetection(value: string, delay = 140): { detection: Detection | null; pending: boolean } {
  const [detection, setDetection] = useState<Detection | null>(null);
  const [pending, setPending] = useState(false);
  useEffect(() => {
    const q = value.trim();
    if (!q) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- clear when the input empties
      setDetection(null);
      setPending(false);
      return;
    }
    setPending(true);
    const controller = new AbortController();
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/detect?q=${encodeURIComponent(q)}`, { signal: controller.signal });
        if (res.ok) setDetection((await res.json()) as Detection);
      } catch {
        /* aborted or offline */
      } finally {
        if (!controller.signal.aborted) setPending(false);
      }
    }, delay);
    return () => {
      clearTimeout(t);
      controller.abort();
    };
  }, [value, delay]);
  return { detection, pending };
}
