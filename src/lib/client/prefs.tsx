"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { TimeZonePref } from "./format";

export interface Prefs {
  density: "comfortable" | "compact";
  motion: "system" | "reduced" | "full";
  tz: TimeZonePref;
  defang: boolean;
  rail: "expanded" | "collapsed";
}

export const DEFAULT_PREFS: Prefs = { density: "comfortable", motion: "system", tz: "utc", defang: false, rail: "expanded" };
export const PREFS_KEY = "nops.prefs.v1";

/** Runs before first paint (inline, nonce'd) so stored preferences never flash. */
export const PREFS_BOOT_SCRIPT = `(function(){try{var p=JSON.parse(localStorage.getItem(${JSON.stringify(PREFS_KEY)})||"{}");var d=document.documentElement;if(p.density==="compact")d.dataset.density="compact";if(p.motion&&p.motion!=="system")d.dataset.motion=p.motion;if(p.rail==="collapsed")d.dataset.rail="collapsed";}catch(e){}})();`;

function apply(p: Prefs) {
  const d = document.documentElement;
  if (p.density === "compact") d.dataset.density = "compact";
  else delete d.dataset.density;
  if (p.motion !== "system") d.dataset.motion = p.motion;
  else delete d.dataset.motion;
  if (p.rail === "collapsed") d.dataset.rail = "collapsed";
  else delete d.dataset.rail;
}

interface PrefsContext {
  prefs: Prefs;
  setPref: <K extends keyof Prefs>(key: K, value: Prefs[K]) => void;
  reset: () => void;
}

const Ctx = createContext<PrefsContext>({ prefs: DEFAULT_PREFS, setPref: () => undefined, reset: () => undefined });

export function PrefsProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Prefs>(DEFAULT_PREFS);

  useEffect(() => {
    try {
      const stored = JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}") as Partial<Prefs>;
      // eslint-disable-next-line react-hooks/set-state-in-effect -- hydrate from storage after mount
      setPrefs({ ...DEFAULT_PREFS, ...stored });
    } catch {
      /* storage unavailable: keep defaults */
    }
  }, []);

  const setPref = useCallback(<K extends keyof Prefs>(key: K, value: Prefs[K]) => {
    setPrefs((prev) => {
      const next = { ...prev, [key]: value };
      try {
        localStorage.setItem(PREFS_KEY, JSON.stringify(next));
      } catch {
        /* ignore */
      }
      apply(next);
      return next;
    });
  }, []);

  const reset = useCallback(() => {
    try {
      localStorage.removeItem(PREFS_KEY);
    } catch {
      /* ignore */
    }
    apply(DEFAULT_PREFS);
    setPrefs(DEFAULT_PREFS);
  }, []);

  const value = useMemo(() => ({ prefs, setPref, reset }), [prefs, setPref, reset]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePrefs() {
  return useContext(Ctx);
}
