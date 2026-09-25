"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";
import type { ProviderMeta } from "@/lib/core/types";

interface CatalogContext {
  list: ProviderMeta[];
  get: (id: string) => ProviderMeta | undefined;
  name: (id: string) => string;
}

const Ctx = createContext<CatalogContext>({ list: [], get: () => undefined, name: (id) => id });

export function CatalogProvider({ providers, children }: { providers: ProviderMeta[]; children: ReactNode }) {
  const value = useMemo(() => {
    const map = new Map(providers.map((p) => [p.id, p]));
    return { list: providers, get: (id: string) => map.get(id), name: (id: string) => map.get(id)?.name ?? id };
  }, [providers]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useCatalog() {
  return useContext(Ctx);
}
