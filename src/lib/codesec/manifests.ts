// Dependency manifest and lockfile parsers. Each returns the packages an
// ecosystem actually resolved to, for OSV.dev queries — not the ranges in a
// manifest, which OSV cannot look up directly.

export type Ecosystem = "npm" | "PyPI" | "Go" | "crates.io" | "Packagist" | "RubyGems" | "Maven";

export interface DepPackage {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  direct: boolean;
  dev: boolean;
  path?: string[];
}

export interface ManifestParseResult {
  file: string;
  ecosystem: Ecosystem;
  packages: DepPackage[];
  warnings: string[];
}

const RECOGNIZED_FILES: { pattern: RegExp; label: string }[] = [
  { pattern: /^package-lock\.json$/, label: "npm (package-lock.json)" },
  { pattern: /^package\.json$/, label: "npm (package.json — declared ranges, not resolved versions)" },
  { pattern: /^yarn\.lock$/, label: "Yarn (yarn.lock)" },
  { pattern: /^pnpm-lock\.yaml$/, label: "pnpm (pnpm-lock.yaml)" },
  { pattern: /^requirements(-\w+)?\.txt$/, label: "pip (requirements.txt)" },
  { pattern: /^Pipfile\.lock$/, label: "Pipenv (Pipfile.lock)" },
  { pattern: /^poetry\.lock$/, label: "Poetry (poetry.lock)" },
  { pattern: /^go\.sum$/, label: "Go modules (go.sum)" },
  { pattern: /^go\.mod$/, label: "Go modules (go.mod — declared, not resolved)" },
  { pattern: /^Cargo\.lock$/, label: "Cargo (Cargo.lock)" },
  { pattern: /^composer\.lock$/, label: "Composer (composer.lock)" },
  { pattern: /^Gemfile\.lock$/, label: "Bundler (Gemfile.lock)" },
  { pattern: /^pom\.xml$/, label: "Maven (pom.xml — declared, not resolved)" },
];

export function recognizeManifest(filename: string): string | null {
  const base = filename.split("/").pop() ?? filename;
  return RECOGNIZED_FILES.find((f) => f.pattern.test(base))?.label ?? null;
}

function dedupe(packages: DepPackage[]): DepPackage[] {
  const map = new Map<string, DepPackage>();
  for (const p of packages) {
    const key = `${p.ecosystem}:${p.name}:${p.version}`;
    const existing = map.get(key);
    if (!existing) map.set(key, p);
    else if (p.direct && !existing.direct) map.set(key, p);
  }
  return [...map.values()];
}

export function parseManifest(filename: string, text: string): ManifestParseResult {
  const base = filename.split("/").pop() ?? filename;
  const warnings: string[] = [];
  try {
    if (base === "package-lock.json") return parsePackageLockJson(base, text, warnings);
    if (base === "package.json") return parsePackageJson(base, text, warnings);
    if (base === "yarn.lock") return parseYarnLock(base, text, warnings);
    if (base === "pnpm-lock.yaml") return parsePnpmLock(base, text, warnings);
    if (/^requirements/.test(base)) return parseRequirementsTxt(base, text, warnings);
    if (base === "Pipfile.lock") return parsePipfileLock(base, text, warnings);
    if (base === "poetry.lock") return parsePoetryLock(base, text, warnings);
    if (base === "go.sum") return parseGoSum(base, text, warnings);
    if (base === "go.mod") return parseGoMod(base, text, warnings);
    if (base === "Cargo.lock") return parseCargoLock(base, text, warnings);
    if (base === "composer.lock") return parseComposerLock(base, text, warnings);
    if (base === "Gemfile.lock") return parseGemfileLock(base, text, warnings);
  } catch (err) {
    warnings.push(`Could not fully parse: ${err instanceof Error ? err.message : String(err)}`);
  }
  return { file: base, ecosystem: "npm", packages: [], warnings: [...warnings, "Unrecognized manifest format"] };
}

function parsePackageLockJson(file: string, text: string, warnings: string[]): ManifestParseResult {
  const j = JSON.parse(text);
  const packages: DepPackage[] = [];
  if (j.packages && typeof j.packages === "object") {
    // npm v7+: keys are node_modules paths; "" is the root.
    for (const [path, info] of Object.entries<Record<string, unknown>>(j.packages)) {
      if (path === "" || !path.startsWith("node_modules/")) continue;
      const segs = path.split("node_modules/").filter(Boolean).map((s) => s.replace(/\/$/, ""));
      const name = segs[segs.length - 1];
      const version = info.version as string | undefined;
      if (!name || !version) continue;
      packages.push({ name, version, ecosystem: "npm", direct: segs.length === 1, dev: !!info.dev, path: segs });
    }
  } else if (j.dependencies && typeof j.dependencies === "object") {
    // legacy v1
    const walk = (deps: Record<string, unknown>, ancestry: string[]) => {
      for (const [name, info0] of Object.entries(deps) as [string, Record<string, unknown>][]) {
        const version = info0.version as string | undefined;
        if (version) packages.push({ name, version, ecosystem: "npm", direct: ancestry.length === 0, dev: !!info0.dev, path: [...ancestry, name] });
        if (info0.dependencies) walk(info0.dependencies as Record<string, unknown>, [...ancestry, name]);
      }
    };
    walk(j.dependencies, []);
  } else warnings.push("No dependency tree found");
  return { file, ecosystem: "npm", packages: dedupe(packages), warnings };
}

function parsePackageJson(file: string, text: string, warnings: string[]): ManifestParseResult {
  const j = JSON.parse(text);
  warnings.push("package.json holds version ranges, not resolved versions; results are approximate. Prefer package-lock.json.");
  const packages: DepPackage[] = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, range] of Object.entries<string>(j[field] ?? {})) {
      const v = String(range).replace(/^[\^~>=<]+/, "").split(/[\s|]/)[0];
      if (/^\d/.test(v)) packages.push({ name, version: v, ecosystem: "npm", direct: true, dev: field === "devDependencies" });
    }
  }
  return { file, ecosystem: "npm", packages: dedupe(packages), warnings };
}

function parseYarnLock(file: string, text: string, warnings: string[]): ManifestParseResult {
  const packages: DepPackage[] = [];
  const blocks = text.split(/\n\n+/);
  for (const block of blocks) {
    const header = /^("?)((?:@[^/,"]+\/)?[^@,"]+)\1@[^\n]*:/m.exec(block);
    const version = /^\s+version\s+"?([^"\n]+)"?/m.exec(block);
    if (header && version) packages.push({ name: header[2], version: version[1], ecosystem: "npm", direct: true, dev: false });
  }
  if (!packages.length) warnings.push("Could not find any package entries");
  return { file, ecosystem: "npm", packages: dedupe(packages), warnings };
}

function parsePnpmLock(file: string, text: string, warnings: string[]): ManifestParseResult {
  const packages: DepPackage[] = [];
  // Lines like "  /lodash@4.17.21:" or "  /@scope/name@1.2.3:" (lockfile v5/v6).
  for (const m of text.matchAll(/^\s*\/?(@[^/@\n]+\/[^@\n]+|[^@/\n]+)@([\d][^():\n]*?)(?:\([^)]*\))?:\s*$/gm)) packages.push({ name: m[1], version: m[2].trim(), ecosystem: "npm", direct: true, dev: false });
  // packages: entries "'/lodash/4.17.21':" (older) — best effort, not exhaustive.
  if (!packages.length) warnings.push("pnpm-lock.yaml format not fully recognised; try package.json instead");
  return { file, ecosystem: "npm", packages: dedupe(packages), warnings };
}

function parseRequirementsTxt(file: string, text: string, warnings: string[]): ManifestParseResult {
  const packages: DepPackage[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([\w.\-+]+)/.exec(line);
    if (m) packages.push({ name: m[1].replace(/\[.*\]$/, ""), version: m[2], ecosystem: "PyPI", direct: true, dev: false });
    else if (/[<>=~!]/.test(line)) warnings.push(`Unpinned or ranged requirement skipped: ${line.slice(0, 60)}`);
  }
  return { file, ecosystem: "PyPI", packages: dedupe(packages), warnings };
}

function parsePipfileLock(file: string, text: string, warnings: string[]): ManifestParseResult {
  const j = JSON.parse(text);
  const packages: DepPackage[] = [];
  for (const section of ["default", "develop"]) {
    for (const [name, info] of Object.entries(j[section] ?? {}) as [string, Record<string, unknown>][]) {
      const v = typeof info.version === "string" ? info.version.replace(/^==/, "") : undefined;
      if (v) packages.push({ name, version: v, ecosystem: "PyPI", direct: true, dev: section === "develop" });
    }
  }
  if (!packages.length) warnings.push("No pinned packages found");
  return { file, ecosystem: "PyPI", packages: dedupe(packages), warnings };
}

function parsePoetryLock(file: string, text: string, warnings: string[]): ManifestParseResult {
  const packages: DepPackage[] = [];
  for (const block of text.split(/\n\[\[package\]\]\n/)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block);
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block);
    const category = /^category\s*=\s*"([^"]+)"/m.exec(block);
    if (name && version) packages.push({ name: name[1], version: version[1], ecosystem: "PyPI", direct: true, dev: category?.[1] === "dev" });
  }
  if (!packages.length) warnings.push("No [[package]] entries found");
  return { file, ecosystem: "PyPI", packages: dedupe(packages), warnings };
}

function parseGoSum(file: string, text: string, warnings: string[]): ManifestParseResult {
  const packages: DepPackage[] = [];
  const seen = new Set<string>();
  for (const line of text.split("\n")) {
    const m = /^(\S+)\s+(v[\d][^\s/]*)(\/go\.mod)?\s+/.exec(line);
    if (!m || m[3]) continue; // skip the /go.mod checksum line, keep the module line
    const key = `${m[1]}@${m[2]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    packages.push({ name: m[1], version: m[2].replace(/^v/, ""), ecosystem: "Go", direct: true, dev: false });
  }
  if (!packages.length) warnings.push("No module lines found");
  return { file, ecosystem: "Go", packages: dedupe(packages), warnings };
}

function parseGoMod(file: string, text: string, warnings: string[]): ManifestParseResult {
  warnings.push("go.mod holds direct requirements only, not the resolved module graph; prefer go.sum.");
  const packages: DepPackage[] = [];
  const block = /require\s*\(([\s\S]*?)\)/.exec(text);
  const lines = block ? block[1].split("\n") : text.split("\n").filter((l) => l.trim().startsWith("require "));
  for (const raw of lines) {
    const m = /^\s*(?:require\s+)?(\S+)\s+(v[\d][^\s]*)/.exec(raw.split("//")[0]);
    if (m) packages.push({ name: m[1], version: m[2].replace(/^v/, ""), ecosystem: "Go", direct: true, dev: false });
  }
  return { file, ecosystem: "Go", packages: dedupe(packages), warnings };
}

function parseCargoLock(file: string, text: string, warnings: string[]): ManifestParseResult {
  const packages: DepPackage[] = [];
  for (const block of text.split(/\n\[\[package\]\]\n/)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block);
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block);
    if (name && version) packages.push({ name: name[1], version: version[1], ecosystem: "crates.io", direct: true, dev: false });
  }
  if (!packages.length) warnings.push("No [[package]] entries found");
  return { file, ecosystem: "crates.io", packages: dedupe(packages), warnings };
}

function parseComposerLock(file: string, text: string, warnings: string[]): ManifestParseResult {
  const j = JSON.parse(text);
  const packages: DepPackage[] = [];
  for (const section of ["packages", "packages-dev"]) {
    for (const p of j[section] ?? []) if (p.name && p.version) packages.push({ name: p.name, version: String(p.version).replace(/^v/, ""), ecosystem: "Packagist", direct: true, dev: section === "packages-dev" });
  }
  if (!packages.length) warnings.push("No packages found");
  return { file, ecosystem: "Packagist", packages: dedupe(packages), warnings };
}

function parseGemfileLock(file: string, text: string, warnings: string[]): ManifestParseResult {
  const packages: DepPackage[] = [];
  const section = /GEM\n(?:.*\n)*?\s{4}specs:\n([\s\S]*?)(?:\n\n|\nPLATFORMS)/.exec(text);
  const body = section ? section[1] : text;
  for (const m of body.matchAll(/^\s{6}([A-Za-z0-9_.\-]+) \(([^)]+)\)/gm)) packages.push({ name: m[1], version: m[2], ecosystem: "RubyGems", direct: true, dev: false });
  if (!packages.length) warnings.push("No gem specs found");
  return { file, ecosystem: "RubyGems", packages: dedupe(packages), warnings };
}
