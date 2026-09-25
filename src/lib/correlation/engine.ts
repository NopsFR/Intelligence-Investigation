import type { RelationshipRecord } from "@/types/investigation";
import type { ProviderOutcome } from "@/types/provider";

let counter = 0;
function nextId(): string {
  counter += 1;
  return `rel-${Date.now()}-${counter}`;
}

/**
 * Builds the relationship graph edges strictly from what providers reported
 * — every edge carries the provider that supplied it as evidence. No edge is
 * invented: this only re-shapes `normalized.relationships` already produced
 * by provider adapters, plus a small number of structural edges (e.g. DNS
 * answers) that are directly observable from the same data.
 */
export function buildRelationships(observable: string, outcomes: ProviderOutcome[]): RelationshipRecord[] {
  const relationships: RelationshipRecord[] = [];
  const now = new Date().toISOString();

  for (const outcome of outcomes) {
    const rels = outcome.normalized?.relationships ?? [];
    for (const r of rels) {
      relationships.push({
        id: nextId(),
        sourceNode: r.sourceNode,
        targetNode: r.targetNode,
        relationType: r.relationType,
        sourceProvider: outcome.provider,
        evidence: r.evidence,
        observedAt: outcome.retrievedAt,
      });
    }

    // Structural DNS edges: domain -> resolved A/AAAA address.
    if ((outcome.provider === "cloudflare-dns" || outcome.provider === "google-dns") && outcome.normalized?.fields) {
      const fields = outcome.normalized.fields as Record<string, string[]>;
      for (const recordType of ["A", "AAAA"] as const) {
        for (const address of fields[recordType] ?? []) {
          relationships.push({
            id: nextId(),
            sourceNode: observable,
            targetNode: address,
            relationType: recordType === "A" ? "resolves_to_ipv4" : "resolves_to_ipv6",
            sourceProvider: outcome.provider,
            evidence: `${recordType} record returned by ${outcome.provider === "cloudflare-dns" ? "Cloudflare" : "Google"} DNS-over-HTTPS.`,
            observedAt: now,
          });
        }
      }
    }
  }

  // De-duplicate identical edges reported by more than one provider by
  // merging the evidence rather than showing the same edge twice.
  const seen = new Map<string, RelationshipRecord>();
  for (const r of relationships) {
    const key = `${r.sourceNode}|${r.targetNode}|${r.relationType}`;
    const existing = seen.get(key);
    if (existing) {
      if (!existing.sourceProvider.includes(r.sourceProvider)) {
        existing.sourceProvider = `${existing.sourceProvider}, ${r.sourceProvider}`;
      }
    } else {
      seen.set(key, { ...r });
    }
  }

  return Array.from(seen.values());
}
