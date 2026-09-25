"use client";

import { useCallback, useEffect, useRef } from "react";

/**
 * Request/response wrapper over a dedicated worker. The worker is created
 * lazily on first use and terminated with the component.
 */
export function useWorker<Req, Res>(factory: () => Worker) {
  const worker = useRef<Worker | null>(null);
  const pending = useRef(new Map<number, { resolve: (v: Res) => void; reject: (e: Error) => void }>());
  const seq = useRef(0);

  useEffect(() => {
    const map = pending.current;
    return () => {
      worker.current?.terminate();
      worker.current = null;
      for (const p of map.values()) p.reject(new Error("cancelled"));
      map.clear();
    };
  }, []);

  return useCallback(
    (payload: Req): Promise<Res> => {
      if (!worker.current) {
        const w = factory();
        w.onmessage = (e: MessageEvent<{ id: number; ok: boolean; error?: string } & Record<string, unknown>>) => {
          const p = pending.current.get(e.data.id);
          if (!p) return;
          pending.current.delete(e.data.id);
          if (e.data.ok) p.resolve(e.data as unknown as Res);
          else p.reject(new Error(e.data.error ?? "Worker failed"));
        };
        w.onerror = (e) => {
          for (const p of pending.current.values()) p.reject(new Error(e.message || "Worker crashed"));
          pending.current.clear();
          worker.current?.terminate();
          worker.current = null;
        };
        worker.current = w;
      }
      const id = ++seq.current;
      return new Promise<Res>((resolve, reject) => {
        pending.current.set(id, { resolve, reject });
        worker.current!.postMessage({ id, ...(payload as object) });
      });
    },
    [factory]
  );
}
