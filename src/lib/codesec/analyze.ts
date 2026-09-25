import type { Severity } from "@/lib/core/types";
import { api } from "@/lib/client/api";
import { detectIacKind, scanIacFile, type IacFinding } from "./iac";
import { parseManifest, recognizeManifest, type DepPackage, type ManifestParseResult } from "./manifests";
import { SECRET_RULES, scanSecrets, type SecretMatch } from "./secrets";

export interface CodeFile {
  path: string;
  text: string;
  size: number;
}

export interface AdvisorySummary {
  id: string;
  summary: string;
  severity: Severity;
  cvss?: number;
  aliases: string[];
  references: string[];
  fixedIn?: string;
}

export interface DependencyResult extends DepPackage {
  file: string;
  advisories: AdvisorySummary[];
}

export interface SecretFinding extends SecretMatch {
  file: string;
}

export interface WorkspaceReport {
  files: number;
  bytes: number;
  manifests: ManifestParseResult[];
  dependencies: DependencyResult[];
  secrets: SecretFinding[];
  iac: (IacFinding & { file: string })[];
  osvErrors: string[];
  osvQueried: number;
  durationMs: number;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const CVSS_BAND: [number, Severity][] = [
  [9, "CRITICAL"],
  [7, "HIGH"],
  [4, "MEDIUM"],
  [0.1, "LOW"],
];

function severityFromOsv(v: { severity?: { type: string; score: string }[]; database_specific?: Record<string, unknown> }): { severity: Severity; cvss?: number } {
  const cvssEntry = v.severity?.find((s) => s.type.startsWith("CVSS"));
  if (cvssEntry) {
    const m = /\/AV:.*?$/.test(cvssEntry.score) ? null : null;
    void m;
    const scoreMatch = cvssEntry.score.match(/(\d+\.\d+)$/);
    const numeric = Number(scoreMatch?.[1]);
    if (Number.isFinite(numeric)) return { severity: CVSS_BAND.find(([t]) => numeric >= t)?.[1] ?? "LOW", cvss: numeric };
  }
  const sev = (v.database_specific?.severity as string | undefined)?.toUpperCase();
  if (sev === "CRITICAL") return { severity: "CRITICAL" };
  if (sev === "HIGH") return { severity: "HIGH" };
  if (sev === "MODERATE" || sev === "MEDIUM") return { severity: "MEDIUM" };
  if (sev === "LOW") return { severity: "LOW" };
  return { severity: "MEDIUM" };
}

function fixedVersion(affected: { ranges?: { events: Record<string, string>[] }[] }[] | undefined): string | undefined {
  for (const a of affected ?? []) for (const r of a.ranges ?? []) for (const e of r.events) if (e.fixed) return e.fixed;
  return undefined;
}

export const MAX_WORKSPACE_FILES = 3000;
export const MAX_FILE_BYTES = 4 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 80 * 1024 * 1024;

/** Files that never carry secrets or app logic worth scanning, so are skipped by default. */
export function skippableFile(path: string): boolean {
  return /(^|\/)(node_modules|\.git|dist|build|target|vendor|\.next|__pycache__|\.venv|venv)\//.test(path) || /\.(png|jpe?g|gif|webp|ico|svg|woff2?|ttf|eot|mp4|mp3|zip|gz|tar|7z|pdf|lock\.bak)$/i.test(path);
}

export async function analyzeWorkspace(files: CodeFile[], opts: { queryOsv?: boolean } = {}): Promise<WorkspaceReport> {
  const started = Date.now();
  const manifests: ManifestParseResult[] = [];
  const secrets: SecretFinding[] = [];
  const iac: (IacFinding & { file: string })[] = [];
  let bytes = 0;

  for (const f of files) {
    bytes += f.size;
    if (recognizeManifest(f.path)) manifests.push(parseManifest(f.path, f.text));
    for (const s of scanSecrets(f.text)) secrets.push({ ...s, file: f.path });
    if (detectIacKind(f.path, f.text) !== "unknown") {
      const { findings } = scanIacFile(f.path, f.text);
      for (const finding of findings) iac.push({ ...finding, file: f.path });
    }
  }

  const allPackages = manifests.flatMap((m) => m.packages.map((p) => ({ ...p, file: m.file })));
  const dependencies: DependencyResult[] = allPackages.map((p) => ({ ...p, advisories: [] }));
  let osvErrors: string[] = [];
  let osvQueried = 0;

  if (opts.queryOsv !== false && allPackages.length) {
    const unique = [...new Map(allPackages.map((p) => [`${p.ecosystem}:${p.name}:${p.version}`, p])).values()];
    try {
      const res = await api<{ results: Record<string, AdvisorySummaryRaw[]>; errors: string[]; queried: number }>("/api/codesec/osv", {
        method: "POST",
        json: { packages: unique.slice(0, 1000).map((p) => ({ name: p.name, version: p.version, ecosystem: p.ecosystem })) },
      });
      osvErrors = res.errors;
      osvQueried = res.queried;
      const byKey = res.results;
      for (const dep of dependencies) {
        const key = `${dep.ecosystem}:${dep.name}:${dep.version}`;
        const vulns = byKey[key] ?? [];
        dep.advisories = vulns.map((v) => {
          const { severity, cvss } = severityFromOsv(v);
          return { id: v.id, summary: v.summary ?? v.details?.slice(0, 200) ?? v.id, severity, cvss, aliases: v.aliases ?? [], references: (v.references ?? []).map((r) => r.url).slice(0, 5), fixedIn: fixedVersion(v.affected) };
        });
      }
    } catch (err) {
      osvErrors = [err instanceof Error ? err.message : String(err)];
    }
  }

  return {
    files: files.length,
    bytes,
    manifests,
    dependencies: dependencies.sort((a, b) => (worstSeverity(b.advisories) === worstSeverity(a.advisories) ? 0 : SEVERITY_ORDER.indexOf(worstSeverity(a.advisories)) - SEVERITY_ORDER.indexOf(worstSeverity(b.advisories)))),
    secrets: secrets.sort((a, b) => (a.confidence === b.confidence ? 0 : a.confidence === "high" ? -1 : 1)),
    iac: iac.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)),
    osvErrors,
    osvQueried,
    durationMs: Date.now() - started,
  };
}

interface AdvisorySummaryRaw {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: Record<string, unknown>;
  affected?: { ranges?: { events: Record<string, string>[] }[] }[];
  references?: { url: string }[];
}

export function worstSeverity(advisories: AdvisorySummary[]): Severity {
  return advisories.reduce<Severity>((worst, a) => (SEVERITY_ORDER.indexOf(a.severity) < SEVERITY_ORDER.indexOf(worst) ? a.severity : worst), "INFO");
}

export { SECRET_RULES };
