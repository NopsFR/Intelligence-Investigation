import type { NodeType, ObservableType, RelationshipRecord } from "@/lib/core/types";

export interface GraphNode {
  key: string;
  type: NodeType;
  value: string;
  label?: string;
  root: boolean;
  degree: number;
  depth: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  providers: string[];
  evidence: string[];
}

export const ROOT_NODE_TYPE: Record<ObservableType, NodeType> = {
  IPV4: "ip",
  IPV6: "ip",
  DOMAIN: "domain",
  URL: "url",
  EMAIL: "email",
  MD5: "hash",
  SHA1: "hash",
  SHA256: "hash",
  CVE: "cve",
  ASN: "asn",
  CERT_SHA256: "certificate",
};

export const NODE_STYLE: Record<NodeType, { color: string; glyph: string; label: string }> = {
  ip: { color: "#6b93b5", glyph: "IP", label: "IP address" },
  prefix: { color: "#6b93b5", glyph: "NET", label: "Prefix" },
  asn: { color: "#6b93b5", glyph: "AS", label: "Autonomous system" },
  organization: { color: "#6b93b5", glyph: "ORG", label: "Organisation" },
  domain: { color: "#b4b4af", glyph: "DOM", label: "Domain" },
  url: { color: "#b4b4af", glyph: "URL", label: "URL" },
  email: { color: "#b4b4af", glyph: "@", label: "Email" },
  certificate: { color: "#8fae9d", glyph: "CRT", label: "Certificate" },
  hash: { color: "#c9b37e", glyph: "#", label: "File hash" },
  malware: { color: "#e0343d", glyph: "MAL", label: "Malware family" },
  cve: { color: "#e8743b", glyph: "CVE", label: "Vulnerability" },
  product: { color: "#e8743b", glyph: "PRD", label: "Product" },
  port: { color: "#e8743b", glyph: "PRT", label: "Port" },
  technique: { color: "#a8bfd6", glyph: "T", label: "ATT&CK technique" },
  software: { color: "#a8bfd6", glyph: "S", label: "ATT&CK software" },
  group: { color: "#a8bfd6", glyph: "G", label: "ATT&CK group" },
};

/** Types that can be investigated directly from the graph. */
export const PIVOTABLE: Partial<Record<NodeType, true>> = { ip: true, domain: true, url: true, email: true, hash: true, cve: true, asn: true, certificate: true };

export const nodeKey = (type: NodeType, value: string) => `${type}:${value.toLowerCase()}`;

export const RELATION_LABELS: Record<string, string> = {
  "resolves-to": "resolves to",
  "alias-of": "alias of",
  "mail-handled-by": "mail handled by",
  "delegated-to": "delegated to",
  "has-ptr": "PTR",
  "announced-by": "announced by",
  "announced-in": "in prefix",
  "registered-with": "registered with",
  "subdomain-of": "subdomain of",
  "presents-certificate": "presents certificate",
  covers: "covers",
  "redirects-to": "redirects to",
  "hosted-on": "hosted on",
  "c2-for": "C2 for",
  "is-family": "family",
  "associated-with": "associated with",
  "documented-as": "ATT&CK entry",
  "possibly-vulnerable-to": "possibly vulnerable to",
};

/**
 * Builds the evidence graph from merged relationship records, keeping only the
 * nodes closest to the investigated observable when the graph is large.
 */
export function buildGraph(relationships: RelationshipRecord[], root: { type: NodeType; value: string }, maxNodes = 120) {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const add = (type: NodeType, value: string, label?: string) => {
    const key = nodeKey(type, value);
    const existing = nodes.get(key);
    if (existing) {
      if (!existing.label && label) existing.label = label;
      return key;
    }
    nodes.set(key, { key, type, value, label, root: false, degree: 0, depth: Infinity });
    return key;
  };
  const rootKey = add(root.type, root.value);
  nodes.get(rootKey)!.root = true;

  for (const r of relationships) {
    const s = add(r.source.type, r.source.value, r.source.label);
    const t = add(r.target.type, r.target.value, r.target.label);
    if (s === t) continue;
    edges.push({ id: r.id, source: s, target: t, type: r.type, providers: r.providers, evidence: r.evidence });
    nodes.get(s)!.degree++;
    nodes.get(t)!.degree++;
  }

  // Breadth-first distance from the root decides what survives the node budget.
  const adjacency = new Map<string, string[]>();
  for (const e of edges) {
    adjacency.set(e.source, [...(adjacency.get(e.source) ?? []), e.target]);
    adjacency.set(e.target, [...(adjacency.get(e.target) ?? []), e.source]);
  }
  const queue = [rootKey];
  nodes.get(rootKey)!.depth = 0;
  while (queue.length) {
    const k = queue.shift()!;
    const d = nodes.get(k)!.depth;
    for (const n of adjacency.get(k) ?? []) {
      const node = nodes.get(n)!;
      if (node.depth === Infinity) {
        node.depth = d + 1;
        queue.push(n);
      }
    }
  }
  const all = [...nodes.values()];
  const kept = all
    .filter((n) => n.depth !== Infinity || n.degree > 0)
    .sort((a, b) => a.depth - b.depth || b.degree - a.degree)
    .slice(0, maxNodes);
  const keep = new Set(kept.map((n) => n.key));
  return {
    nodes: kept,
    edges: edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
    total: all.length,
    rootKey,
  };
}
