"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "./api";

export interface SessionState {
  operator: boolean;
  configured: boolean;
  privateMode: boolean;
  expiresAt?: string;
}

interface SessionContext {
  session: SessionState | null;
  refresh: () => Promise<void>;
  unlock: (token: string) => Promise<void>;
  lock: () => Promise<void>;
}

const Ctx = createContext<SessionContext>({ session: null, refresh: async () => undefined, unlock: async () => undefined, lock: async () => undefined });

export function SessionProvider({ initial, children }: { initial: SessionState; children: ReactNode }) {
  const [session, setSession] = useState<SessionState | null>(initial);
  const refresh = useCallback(async () => {
    try {
      setSession(await api<SessionState>("/api/session"));
    } catch {
      /* keep last known */
    }
  }, []);
  const unlock = useCallback(
    async (token: string) => {
      await api("/api/session", { method: "POST", json: { token } });
      await refresh();
    },
    [refresh]
  );
  const lock = useCallback(async () => {
    await api("/api/session", { method: "DELETE" });
    await refresh();
  }, [refresh]);

  useEffect(() => {
    const onFocus = () => void refresh();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refresh]);

  const value = useMemo(() => ({ session, refresh, unlock, lock }), [session, refresh, unlock, lock]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession() {
  return useContext(Ctx);
}
