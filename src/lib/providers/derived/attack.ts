import "server-only";
import type { NormalizedRelationship } from "@/lib/core/types";
import { loadAttack, matchSoftware } from "@/lib/intel/attack";
import { fact, facts, plural, uniq } from "../helpers";
import { ProviderSkip } from "../runtime";
import type { ProviderDefinition } from "../types";
import { answered } from "./shared";

const SOURCES = ["threatfox", "malwarebazaar", "otx", "feodo", "virustotal", "urlhaus", "hosting"];

export interface AttackSoftwareMatch {
  id: string;
  name: string;
  kind: "malware" | "tool";
  families: string[];
  providers: string[];
  techniqueCount: number;
  groups: { id: string; name: string }[];
}

export interface AttackTechniqueMatch {
  id: string;
  name: string;
  tactics: string[];
  /** Where the link comes from: an ATT&CK software id, or a provider that tagged it directly. */
  via: string[];
}

export const attackMapping: ProviderDefinition = {
  id: "attack",
  code: "ATT",
  name: "ATT&CK mapping",
  vendor: "Derived · MITRE ATT&CK Enterprise",
  category: "correlation",
  kind: "derived",
  description:
    "Maps malware families named by intelligence sources to ATT&CK software entries, and collects the techniques those entries document — plus any techniques sources tagged directly.",
  homepage: "https://attack.mitre.org",
  auth: { type: "none" },
  endpoint: "Local · bundled ATT&CK Enterprise dataset",
  supports: ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"],
  dependsOn: SOURCES,
  cacheTtlSeconds: 0,
  timeoutMs: 10_000,
  async run(ctx) {
    if (!SOURCES.some((id) => answered(ctx, id))) throw new ProviderSkip("No intelligence source answered, so there is nothing to map to ATT&CK");
    const index = await loadAttack();
    const families = new Map<string, Set<string>>();
    const tagged = new Map<string, Set<string>>();
    for (const id of SOURCES) {
      const outcome = answered(ctx, id);
      for (const r of outcome?.result?.relationships ?? []) {
        if (r.target.type === "malware") {
          const set = families.get(r.target.value) ?? new Set();
          set.add(id);
          families.set(r.target.value, set);
        } else if (r.target.type === "technique") {
          const set = tagged.get(r.target.value) ?? new Set();
          set.add(id);
          tagged.set(r.target.value, set);
        }
      }
    }

    const software = new Map<string, AttackSoftwareMatch>();
    const unmatched: string[] = [];
    for (const [family, providers] of families) {
      const s = matchSoftware(index, family);
      if (!s) {
        unmatched.push(family);
        continue;
      }
      const existing = software.get(s.id);
      if (existing) {
        existing.families = uniq([...existing.families, family]);
        existing.providers = uniq([...existing.providers, ...providers]);
        continue;
      }
      const usedBy = index.usedBy.get(s.id) ?? [];
      software.set(s.id, {
        id: s.id,
        name: s.name,
        kind: s.kind,
        families: [family],
        providers: [...providers],
        techniqueCount: (index.uses.get(s.id) ?? []).filter((e) => e.id.startsWith("T")).length,
        groups: usedBy.filter((e) => e.id.startsWith("G")).map((e) => ({ id: e.id, name: index.groups.get(e.id)?.name ?? e.id })),
      });
    }

    const techniques = new Map<string, AttackTechniqueMatch>();
    const addTechnique = (id: string, via: string) => {
      const t = index.techniques.get(id);
      if (!t) return;
      const existing = techniques.get(id);
      if (existing) existing.via = uniq([...existing.via, via]);
      else techniques.set(id, { id, name: t.name, tactics: t.tactics, via: [via] });
    };
    for (const s of software.values()) for (const e of index.uses.get(s.id) ?? []) if (e.id.startsWith("T")) addTechnique(e.id, s.id);
    for (const [id, providers] of tagged) for (const p of providers) addTechnique(id, p);

    if (!software.size && !techniques.size) {
      return {
        summary: families.size ? `No ATT&CK entry for ${[...families.keys()].slice(0, 3).join(", ")}` : "No malware families or techniques reported by sources",
        empty: true,
        listed: false,
        facts: facts(fact("families", "Families reported", [...families.keys()], "list")),
        data: { kind: "attack-mapping", software: [], techniques: [], unmatched, version: index.meta.version },
      };
    }

    const relationships: NormalizedRelationship[] = [...software.values()].flatMap((s) =>
      s.families.map((family) => ({
        source: { type: "malware" as const, value: family },
        target: { type: "software" as const, value: s.id, label: s.name },
        type: "documented-as",
        evidence: `MITRE ATT&CK ${s.kind} entry ${s.id} (name/alias match).`,
      }))
    );
    const byTactic = new Map<string, number>();
    for (const t of techniques.values()) for (const tac of t.tactics) byTactic.set(tac, (byTactic.get(tac) ?? 0) + 1);
    const softwareList = [...software.values()];
    return {
      summary: [softwareList.length ? softwareList.map((s) => `${s.name} (${s.id})`).join(", ") : null, plural(techniques.size, "technique")].filter(Boolean).join(" · "),
      listed: true,
      facts: facts(
        fact("software", "ATT&CK software", softwareList.map((s) => `${s.id} ${s.name}`), "list", true),
        fact("techniques", "Techniques", techniques.size, "number", true),
        fact("tactics", "Tactics covered", byTactic.size, "number"),
        fact("groups", "Groups documented using this software", uniq(softwareList.flatMap((s) => s.groups.map((g) => g.name))).slice(0, 12), "list"),
        fact("unmatched", "Families without an ATT&CK entry", unmatched, "list"),
        fact("version", "ATT&CK version", index.meta.version, "mono")
      ),
      data: {
        kind: "attack-mapping",
        version: index.meta.version,
        software: softwareList,
        techniques: [...techniques.values()].sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true })),
        byTactic: Object.fromEntries(byTactic),
        unmatched,
      },
      // Groups are listed as context (documented users of the software), never as attribution.
      relationships,
    };
  },
};
