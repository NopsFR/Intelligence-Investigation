import "server-only";
import { readFile } from "node:fs/promises";
import path from "node:path";

// MITRE ATT&CK Enterprise, preprocessed by scripts/build-attack-data.mjs from the
// official STIX bundle. Loaded lazily from disk (not bundled) and indexed once.

export interface AttackReference {
  source: string;
  url?: string;
  description?: string;
}

export interface AttackTactic {
  id: string;
  name: string;
  shortname: string;
  description: string;
  url: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  isSubtechnique: boolean;
  parent?: string;
  description: string;
  url: string;
  modified?: string;
  detection?: string;
  references?: AttackReference[];
}

export interface AttackGroup {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  url: string;
  modified?: string;
  references?: AttackReference[];
}

export interface AttackSoftware {
  id: string;
  name: string;
  kind: "malware" | "tool";
  aliases: string[];
  platforms: string[];
  description: string;
  url: string;
  modified?: string;
  references?: AttackReference[];
}

export interface AttackCampaign {
  id: string;
  name: string;
  aliases?: string[];
  description: string;
  url: string;
  firstSeen?: string;
  lastSeen?: string;
}

export interface AttackMitigation {
  id: string;
  name: string;
  description: string;
  url: string;
}

type RelationshipTuple = [source: string, type: "uses" | "mitigates" | "attributed-to" | string, target: string, procedure?: string];

interface AttackDataset {
  meta: { domain: string; name: string; version: string; modified: string; generatedAt: string; source: string; attribution: string };
  tactics: AttackTactic[];
  techniques: AttackTechnique[];
  groups: AttackGroup[];
  software: AttackSoftware[];
  campaigns: AttackCampaign[];
  mitigations: AttackMitigation[];
  relationships: RelationshipTuple[];
}

export type AttackEntityKind = "tactic" | "technique" | "group" | "software" | "campaign" | "mitigation";

export interface AttackEdge {
  id: string;
  procedure?: string;
}

export interface AttackIndex {
  meta: AttackDataset["meta"];
  tactics: AttackTactic[];
  techniques: Map<string, AttackTechnique>;
  groups: Map<string, AttackGroup>;
  software: Map<string, AttackSoftware>;
  campaigns: Map<string, AttackCampaign>;
  mitigations: Map<string, AttackMitigation>;
  /** source id → targets it uses (techniques, software). */
  uses: Map<string, AttackEdge[]>;
  /** target id → sources that use it. */
  usedBy: Map<string, AttackEdge[]>;
  /** technique id → mitigations. */
  mitigatedBy: Map<string, AttackEdge[]>;
  /** mitigation id → techniques. */
  mitigates: Map<string, AttackEdge[]>;
  /** campaign id → groups. */
  attributedTo: Map<string, string[]>;
  /** group id → campaigns. */
  campaignsOf: Map<string, string[]>;
  subtechniques: Map<string, string[]>;
  /** normalised software name/alias → software id. */
  softwareByName: Map<string, string>;
  groupByName: Map<string, string>;
}

let loading: Promise<AttackIndex> | null = null;

export const ATTACK_DATA_PATH = path.join(process.cwd(), "src", "data", "attack", "enterprise.json");

/** Canonical form for matching malware family names across sources ("win.agent_tesla" ≈ "Agent Tesla"). */
export function normalizeFamilyName(name: string): string {
  return name
    .toLowerCase()
    .replace(/^(win|elf|osx|apk|js|php|ps1|py|vbs|jar|ios|symbian|fas)\./, "")
    .replace(/[^a-z0-9]/g, "");
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

function build(data: AttackDataset): AttackIndex {
  const index: AttackIndex = {
    meta: data.meta,
    tactics: data.tactics,
    techniques: new Map(data.techniques.map((t) => [t.id, t])),
    groups: new Map(data.groups.map((g) => [g.id, g])),
    software: new Map(data.software.map((s) => [s.id, s])),
    campaigns: new Map(data.campaigns.map((c) => [c.id, c])),
    mitigations: new Map(data.mitigations.map((m) => [m.id, m])),
    uses: new Map(),
    usedBy: new Map(),
    mitigatedBy: new Map(),
    mitigates: new Map(),
    attributedTo: new Map(),
    campaignsOf: new Map(),
    subtechniques: new Map(),
    softwareByName: new Map(),
    groupByName: new Map(),
  };
  for (const [source, type, target, procedure] of data.relationships) {
    if (type === "uses") {
      push(index.uses, source, { id: target, procedure });
      push(index.usedBy, target, { id: source, procedure });
    } else if (type === "mitigates") {
      push(index.mitigatedBy, target, { id: source, procedure });
      push(index.mitigates, source, { id: target, procedure });
    } else if (type === "attributed-to") {
      push(index.attributedTo, source, target);
      push(index.campaignsOf, target, source);
    }
  }
  for (const t of data.techniques) if (t.parent) push(index.subtechniques, t.parent, t.id);
  for (const s of data.software) {
    for (const n of [s.name, ...s.aliases]) {
      const key = normalizeFamilyName(n);
      // Very short names ("SUGARDUMP" is fine, "BS2005" fine, "Net" is not) produce false matches.
      if (key.length >= 4 && !index.softwareByName.has(key)) index.softwareByName.set(key, s.id);
    }
  }
  for (const g of data.groups) {
    for (const n of [g.name, ...g.aliases]) {
      const key = normalizeFamilyName(n);
      if (key.length >= 3 && !index.groupByName.has(key)) index.groupByName.set(key, g.id);
    }
  }
  return index;
}

export function loadAttack(): Promise<AttackIndex> {
  loading ??= readFile(ATTACK_DATA_PATH, "utf8")
    .then((text) => build(JSON.parse(text) as AttackDataset))
    .catch((err) => {
      loading = null;
      throw err;
    });
  return loading;
}

export function entityKind(id: string): AttackEntityKind | null {
  if (/^TA\d{4}$/.test(id)) return "tactic";
  if (/^T\d{4}(\.\d{3})?$/.test(id)) return "technique";
  if (/^G\d{4}$/.test(id)) return "group";
  if (/^S\d{4}$/.test(id)) return "software";
  if (/^C\d{4}$/.test(id)) return "campaign";
  if (/^M\d{4}$/.test(id)) return "mitigation";
  return null;
}

export function matchSoftware(index: AttackIndex, familyName: string): AttackSoftware | null {
  const id = index.softwareByName.get(normalizeFamilyName(familyName));
  return id ? index.software.get(id) ?? null : null;
}

export interface AttackSearchHit {
  id: string;
  kind: AttackEntityKind;
  name: string;
  detail: string;
  score: number;
}

export function searchAttack(index: AttackIndex, q: string, limit = 25): AttackSearchHit[] {
  const query = q.trim().toLowerCase();
  if (!query) return [];
  const hits: AttackSearchHit[] = [];
  const consider = (id: string, kind: AttackEntityKind, name: string, aliases: string[], detail: string) => {
    const lname = name.toLowerCase();
    let score = 0;
    if (id.toLowerCase() === query) score = 100;
    else if (id.toLowerCase().startsWith(query)) score = 80;
    else if (lname === query) score = 90;
    else if (lname.startsWith(query)) score = 60;
    else if (aliases.some((a) => a.toLowerCase() === query)) score = 70;
    else if (lname.includes(query)) score = 40;
    else if (aliases.some((a) => a.toLowerCase().includes(query))) score = 30;
    if (score) hits.push({ id, kind, name, detail, score });
  };
  for (const t of index.tactics) consider(t.id, "tactic", t.name, [], "Tactic");
  for (const t of index.techniques.values()) consider(t.id, "technique", t.name, [], t.isSubtechnique ? `Sub-technique of ${t.parent}` : "Technique");
  for (const g of index.groups.values()) consider(g.id, "group", g.name, g.aliases, g.aliases.length ? `Group · aka ${g.aliases.slice(0, 3).join(", ")}` : "Group");
  for (const s of index.software.values()) consider(s.id, "software", s.name, s.aliases, s.kind === "malware" ? "Malware" : "Tool");
  for (const c of index.campaigns.values()) consider(c.id, "campaign", c.name, c.aliases ?? [], "Campaign");
  for (const m of index.mitigations.values()) consider(m.id, "mitigation", m.name, [], "Mitigation");
  return hits.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)).slice(0, limit);
}

export interface RelatedEntity {
  id: string;
  name: string;
  kind: AttackEntityKind;
  procedure?: string;
}

function named(index: AttackIndex, id: string): { name: string; kind: AttackEntityKind } | null {
  const kind = entityKind(id);
  if (!kind) return null;
  const e =
    kind === "technique" ? index.techniques.get(id)
    : kind === "group" ? index.groups.get(id)
    : kind === "software" ? index.software.get(id)
    : kind === "campaign" ? index.campaigns.get(id)
    : kind === "mitigation" ? index.mitigations.get(id)
    : index.tactics.find((t) => t.id === id);
  return e ? { name: e.name, kind } : null;
}

function relate(index: AttackIndex, edges: AttackEdge[] | undefined, kind?: AttackEntityKind): RelatedEntity[] {
  const out: RelatedEntity[] = [];
  for (const e of edges ?? []) {
    const n = named(index, e.id);
    if (n && (!kind || n.kind === kind)) out.push({ id: e.id, name: n.name, kind: n.kind, ...(e.procedure ? { procedure: e.procedure } : {}) });
  }
  return out.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));
}

export interface AttackEntityDetails {
  id: string;
  kind: AttackEntityKind;
  entity: AttackTactic | AttackTechnique | AttackGroup | AttackSoftware | AttackCampaign | AttackMitigation;
  tactics?: AttackTactic[];
  parent?: RelatedEntity;
  subtechniques?: RelatedEntity[];
  techniques?: RelatedEntity[];
  groups?: RelatedEntity[];
  software?: RelatedEntity[];
  campaigns?: RelatedEntity[];
  mitigations?: RelatedEntity[];
}

export function attackDetails(index: AttackIndex, id: string): AttackEntityDetails | null {
  const kind = entityKind(id);
  if (!kind) return null;
  switch (kind) {
    case "tactic": {
      const tactic = index.tactics.find((t) => t.id === id);
      if (!tactic) return null;
      const techniques = [...index.techniques.values()]
        .filter((t) => !t.isSubtechnique && t.tactics.includes(tactic.shortname))
        .map((t) => ({ id: t.id, name: t.name, kind: "technique" as const }));
      return { id, kind, entity: tactic, techniques };
    }
    case "technique": {
      const t = index.techniques.get(id);
      if (!t) return null;
      const users = index.usedBy.get(id);
      return {
        id,
        kind,
        entity: t,
        tactics: index.tactics.filter((x) => t.tactics.includes(x.shortname)),
        parent: t.parent ? { id: t.parent, name: index.techniques.get(t.parent)?.name ?? t.parent, kind: "technique" } : undefined,
        subtechniques: (index.subtechniques.get(id) ?? []).map((s) => ({ id: s, name: index.techniques.get(s)?.name ?? s, kind: "technique" as const })),
        groups: relate(index, users, "group"),
        software: relate(index, users, "software"),
        campaigns: relate(index, users, "campaign"),
        mitigations: relate(index, index.mitigatedBy.get(id), "mitigation"),
      };
    }
    case "group": {
      const g = index.groups.get(id);
      if (!g) return null;
      const used = index.uses.get(id);
      return {
        id,
        kind,
        entity: g,
        techniques: relate(index, used, "technique"),
        software: relate(index, used, "software"),
        campaigns: (index.campaignsOf.get(id) ?? []).map((c) => ({ id: c, name: index.campaigns.get(c)?.name ?? c, kind: "campaign" as const })),
      };
    }
    case "software": {
      const s = index.software.get(id);
      if (!s) return null;
      return { id, kind, entity: s, techniques: relate(index, index.uses.get(id), "technique"), groups: relate(index, index.usedBy.get(id), "group"), campaigns: relate(index, index.usedBy.get(id), "campaign") };
    }
    case "campaign": {
      const c = index.campaigns.get(id);
      if (!c) return null;
      const used = index.uses.get(id);
      return {
        id,
        kind,
        entity: c,
        techniques: relate(index, used, "technique"),
        software: relate(index, used, "software"),
        groups: (index.attributedTo.get(id) ?? []).map((g) => ({ id: g, name: index.groups.get(g)?.name ?? g, kind: "group" as const })),
      };
    }
    case "mitigation": {
      const m = index.mitigations.get(id);
      if (!m) return null;
      return { id, kind, entity: m, techniques: relate(index, index.mitigates.get(id), "technique") };
    }
  }
}

/** Technique counts per tactic, for the matrix view. */
export function attackMatrix(index: AttackIndex) {
  return index.tactics.map((tactic) => ({
    tactic: { id: tactic.id, name: tactic.name, shortname: tactic.shortname },
    techniques: [...index.techniques.values()]
      .filter((t) => !t.isSubtechnique && t.tactics.includes(tactic.shortname))
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((t) => ({ id: t.id, name: t.name, subtechniques: (index.subtechniques.get(t.id) ?? []).length })),
  }));
}
