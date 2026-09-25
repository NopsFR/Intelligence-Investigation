import "server-only";
import type { ProviderMeta } from "@/lib/core/types";
import { PROVIDERS } from "./registry";

export function providerCatalog(): ProviderMeta[] {
  return PROVIDERS.map((p) => ({
    id: p.id,
    code: p.code,
    name: p.name,
    vendor: p.vendor,
    category: p.category,
    kind: p.kind,
    active: Boolean(p.active),
    auth: p.auth.type,
    homepage: p.homepage,
    supports: p.supports,
  }));
}
