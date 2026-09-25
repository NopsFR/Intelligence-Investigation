#!/usr/bin/env node
// Distils the official MITRE ATT&CK Enterprise STIX 2.1 bundle into the compact
// dataset served by NOPS. Source: https://github.com/mitre-attack/attack-stix-data
//
//   node scripts/build-attack-data.mjs <path/to/enterprise-attack.json>
//
// Output: src/data/attack/enterprise.json
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const input = process.argv[2];
if (!input) {
  console.error("usage: node scripts/build-attack-data.mjs <enterprise-attack.json>");
  process.exit(1);
}

const bundle = JSON.parse(readFileSync(input, "utf8"));
const objects = bundle.objects.filter((o) => !o.revoked && !o.x_mitre_deprecated);
const byStixId = new Map(objects.map((o) => [o.id, o]));

const externalId = (o) => o.external_references?.find((r) => r.source_name === "mitre-attack")?.external_id;
const attackUrl = (o) => o.external_references?.find((r) => r.source_name === "mitre-attack")?.url;

// ATT&CK prose embeds "(Citation: Name)" markers; references are shipped separately.
const clean = (text) =>
  (text ?? "")
    .replace(/\s*\(Citation:[^)]*\)/g, "")
    .replace(/<code>(.*?)<\/code>/g, "`$1`")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

const references = (o) =>
  (o.external_references ?? [])
    .filter((r) => r.source_name !== "mitre-attack" && r.url)
    .map((r) => ({ source: r.source_name, url: r.url, ...(r.description ? { title: r.description.slice(0, 240) } : {}) }));

const collection = bundle.objects.find((o) => o.type === "x-mitre-collection");
const matrix = objects.find((o) => o.type === "x-mitre-matrix");
const tacticOrder = matrix?.tactic_refs ?? [];

const tactics = tacticOrder
  .map((ref) => byStixId.get(ref))
  .filter(Boolean)
  .map((t) => ({
    id: externalId(t),
    name: t.name,
    shortname: t.x_mitre_shortname,
    description: clean(t.description),
    url: attackUrl(t),
  }));

const techniquesRaw = objects.filter((o) => o.type === "attack-pattern" && externalId(o));
const techniques = techniquesRaw
  .map((t) => {
    const id = externalId(t);
    return {
      id,
      name: t.name,
      tactics: (t.kill_chain_phases ?? []).filter((k) => k.kill_chain_name === "mitre-attack").map((k) => k.phase_name),
      platforms: t.x_mitre_platforms ?? [],
      isSubtechnique: Boolean(t.x_mitre_is_subtechnique),
      parent: t.x_mitre_is_subtechnique ? id.split(".")[0] : undefined,
      description: clean(t.description),
      url: attackUrl(t),
      modified: t.modified,
      references: references(t),
    };
  })
  .sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

const groups = objects
  .filter((o) => o.type === "intrusion-set" && externalId(o))
  .map((g) => ({
    id: externalId(g),
    name: g.name,
    aliases: (g.aliases ?? []).filter((a) => a !== g.name),
    description: clean(g.description),
    url: attackUrl(g),
    modified: g.modified,
    references: references(g),
  }))
  .sort((a, b) => a.name.localeCompare(b.name));

const software = objects
  .filter((o) => (o.type === "malware" || o.type === "tool") && externalId(o))
  .map((s) => ({
    id: externalId(s),
    name: s.name,
    kind: s.type,
    aliases: (s.x_mitre_aliases ?? []).filter((a) => a !== s.name),
    platforms: s.x_mitre_platforms ?? [],
    description: clean(s.description),
    url: attackUrl(s),
    modified: s.modified,
    references: references(s),
  }))
  .sort((a, b) => a.name.localeCompare(b.name));

const campaigns = objects
  .filter((o) => o.type === "campaign" && externalId(o))
  .map((c) => ({
    id: externalId(c),
    name: c.name,
    description: clean(c.description),
    firstSeen: c.first_seen,
    lastSeen: c.last_seen,
    url: attackUrl(c),
  }))
  .sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

const mitigations = objects
  .filter((o) => o.type === "course-of-action" && externalId(o))
  .map((m) => ({ id: externalId(m), name: m.name, description: clean(m.description), url: attackUrl(m) }))
  .sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

// Detection strategies (ATT&CK v18+): each bundles platform-specific analytics
// with the log sources they need. Linked to techniques by "detects" relationships.
const dataComponents = new Map(objects.filter((o) => o.type === "x-mitre-data-component").map((d) => [d.id, { id: externalId(d), name: d.name }]));
const analytics = new Map(objects.filter((o) => o.type === "x-mitre-analytic").map((a) => [a.id, a]));
const detectionStrategies = objects
  .filter((o) => o.type === "x-mitre-detection-strategy" && externalId(o))
  .map((d) => ({
    id: externalId(d),
    name: d.name,
    url: attackUrl(d),
    analytics: (d.x_mitre_analytic_refs ?? [])
      .map((ref) => analytics.get(ref))
      .filter(Boolean)
      .map((a) => ({
        id: externalId(a),
        platforms: a.x_mitre_platforms ?? [],
        description: clean(a.description),
        logSources: (a.x_mitre_log_source_references ?? []).map((l) => ({
          component: dataComponents.get(l.x_mitre_data_component_ref)?.name ?? null,
          name: l.name,
          channel: l.channel,
        })),
      })),
  }))
  .sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

// Relationships are stored as [sourceId, type, targetId, procedure?] tuples keyed by
// ATT&CK IDs so the runtime never needs STIX identifiers.
const relationships = [];
for (const r of objects) {
  if (r.type !== "relationship") continue;
  if (!["uses", "mitigates", "attributed-to", "detects"].includes(r.relationship_type)) continue;
  const source = byStixId.get(r.source_ref);
  const target = byStixId.get(r.target_ref);
  if (!source || !target) continue;
  const s = externalId(source);
  const t = externalId(target);
  if (!s || !t) continue;
  const procedure = r.relationship_type === "uses" ? clean(r.description) : "";
  relationships.push(procedure ? [s, r.relationship_type, t, procedure] : [s, r.relationship_type, t]);
}

const output = {
  meta: {
    domain: "enterprise-attack",
    name: collection?.name ?? "Enterprise ATT&CK",
    version: collection?.x_mitre_version ?? null,
    modified: collection?.modified ?? null,
    generatedAt: new Date().toISOString(),
    source: "https://github.com/mitre-attack/attack-stix-data",
    attribution:
      "MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Content © The MITRE Corporation, reproduced and distributed with the permission of The MITRE Corporation under the ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).",
  },
  tactics,
  techniques,
  groups,
  software,
  campaigns,
  mitigations,
  detectionStrategies,
  relationships,
};

const outPath = resolve("src/data/attack/enterprise.json");
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(output));
console.log(
  `ATT&CK ${output.meta.version}: ${tactics.length} tactics, ${techniques.length} techniques, ${groups.length} groups, ` +
    `${software.length} software, ${campaigns.length} campaigns, ${mitigations.length} mitigations, ${detectionStrategies.length} detection strategies, ${relationships.length} relationships`
);
