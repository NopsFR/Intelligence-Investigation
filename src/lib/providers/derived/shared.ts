import "server-only";
import { ANSWERED_STATUSES, type ProviderOutcome } from "@/lib/core/types";
import type { ProviderRunContext } from "../types";

/** A dependency outcome that actually answered (SUCCESS / PARTIAL / EMPTY). */
export function answered(ctx: ProviderRunContext, id: string): ProviderOutcome | undefined {
  const o = ctx.dependencies.get(id);
  return o && ANSWERED_STATUSES.has(o.status) ? o : undefined;
}

/** Typed access to a dependency's `data` payload when it has the expected kind. */
export function dataOf<T extends { kind: string }>(ctx: ProviderRunContext, id: string, kind: T["kind"] | T["kind"][]): T | undefined {
  const d = answered(ctx, id)?.result?.data;
  if (!d) return undefined;
  const kinds = Array.isArray(kind) ? kind : [kind];
  return kinds.includes(d.kind) ? (d as unknown as T) : undefined;
}

export function allOutcomes(ctx: ProviderRunContext): ProviderOutcome[] {
  return [...ctx.dependencies.values()];
}
