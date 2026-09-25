"use client";

import { Download, FolderUp, Package, RotateCcw, ShieldCheck } from "lucide-react";
import { useCallback, useMemo, useRef, useState } from "react";
import { analyzeWorkspace, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_WORKSPACE_FILES, skippableFile, worstSeverity, type CodeFile, type WorkspaceReport } from "@/lib/codesec/analyze";
import { SEVERITY_COLOR } from "@/components/ui/badges";
import { ErrorNote, Panel, Stat } from "@/components/ui/primitives";
import { formatBytes } from "@/components/ui/workbench";
import { Chip, DataTable, LocalFindings, Mono, downloadJson } from "../common";

type State = { phase: "idle" } | { phase: "working"; name: string } | { phase: "done"; report: WorkspaceReport } | { phase: "error"; message: string };

async function readTree(list: FileList | File[]): Promise<CodeFile[]> {
  const files = Array.from(list);
  const out: CodeFile[] = [];
  let total = 0;
  for (const f of files) {
    const path = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
    if (skippableFile(path)) continue;
    if (f.size > MAX_FILE_BYTES) continue;
    total += f.size;
    if (total > MAX_TOTAL_BYTES || out.length >= MAX_WORKSPACE_FILES) break;
    try {
      const text = await f.text();
      out.push({ path, text, size: f.size });
    } catch {
      // skip unreadable (binary) files
    }
  }
  return out;
}

export function CodeSecurity() {
  const [state, setState] = useState<State>({ phase: "idle" });
  const folderInput = useRef<HTMLInputElement>(null);
  const filesInput = useRef<HTMLInputElement>(null);

  const run = useCallback(async (list: FileList) => {
    setState({ phase: "working", name: `${list.length} file${list.length === 1 ? "" : "s"}` });
    try {
      const files = await readTree(list);
      if (!files.length) {
        setState({ phase: "error", message: "No readable text files were found (binaries, node_modules, .git and similar are skipped)." });
        return;
      }
      const report = await analyzeWorkspace(files);
      setState({ phase: "done", report });
    } catch (err) {
      setState({ phase: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }, []);

  if (state.phase !== "done") {
    return (
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="flex flex-col gap-3">
          <div className="grid-canvas flex flex-col items-center gap-4 rounded-[3px] border border-dashed border-line-3 px-6 py-12 text-center">
            <div className="grid h-10 w-10 place-items-center rounded-[3px] border border-line-2 bg-ink-1 text-fg-2" aria-hidden>
              <FolderUp size={17} />
            </div>
            <div>
              <div className="text-sm font-semibold text-fg-1">{state.phase === "working" ? `Analysing ${state.name}` : "Choose a project folder or files"}</div>
              <p className="mt-1 max-w-lg text-xs text-fg-3">Dependency manifests (package-lock.json, requirements.txt, go.sum, Cargo.lock, …), Dockerfiles, docker-compose, Kubernetes manifests, Terraform and GitHub Actions workflows, and source files for hardcoded secrets.</p>
            </div>
            <div className="flex gap-2">
              <button type="button" className="btn" onClick={() => folderInput.current?.click()}>
                <FolderUp size={14} /> Choose a folder
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => filesInput.current?.click()}>
                Choose files
              </button>
            </div>
            <div className="mt-1 inline-flex items-center gap-1.5 text-[11px] text-fg-4">
              <ShieldCheck size={11} /> Read in your browser — files are never uploaded · up to {MAX_WORKSPACE_FILES.toLocaleString()} files
            </div>
            <input ref={folderInput} type="file" className="sr-only" tabIndex={-1} {...({ webkitdirectory: "", directory: "" } as Record<string, string>)} onChange={(e) => e.target.files && void run(e.target.files)} />
            <input ref={filesInput} type="file" multiple className="sr-only" tabIndex={-1} onChange={(e) => e.target.files && void run(e.target.files)} />
          </div>
          {state.phase === "error" && <ErrorNote title="Could not analyse this folder">{state.message}</ErrorNote>}
        </div>
        <Panel title="What runs where">
          <ul className="flex flex-col gap-2.5 text-sm text-fg-2">
            <li className="flex gap-2.5">
              <ShieldCheck size={15} className="mt-0.5 shrink-0 text-ok" />
              <span>Secret scanning, manifest parsing and infrastructure-as-code checks run entirely in your browser.</span>
            </li>
            <li className="flex gap-2.5">
              <Package size={15} className="mt-0.5 shrink-0 text-fg-3" />
              <span>Only (package name, version, ecosystem) triples — never file contents or paths — are sent to OSV.dev for advisories.</span>
            </li>
          </ul>
        </Panel>
      </div>
    );
  }
  return <Report report={state.report} reset={() => setState({ phase: "idle" })} />;
}

function Report({ report: r, reset }: { report: WorkspaceReport; reset: () => void }) {
  const { vulnerable, worst, findings } = useMemo(() => {
    const vuln = r.dependencies.filter((d) => d.advisories.length > 0);
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const w = [...r.iac.map((f) => f.severity), ...vuln.map((d) => worstSeverity(d.advisories)), ...(r.secrets.length ? ["HIGH" as const] : [])].sort((a, b) => order.indexOf(a) - order.indexOf(b))[0];
    const f = [
      ...r.iac.map((x) => ({ id: x.id, severity: x.severity, title: `${x.title} (${x.file}${x.line ? `:${x.line}` : ""})`, detail: x.detail, evidence: x.evidence, basis: "structure" })),
      ...(r.secrets.length ? [{ id: "code.secrets", severity: r.secrets.some((s) => s.confidence === "high") ? ("HIGH" as const) : ("MEDIUM" as const), title: `${r.secrets.length} likely secret${r.secrets.length === 1 ? "" : "s"} in source`, detail: "Hardcoded credentials found by pattern and entropy. Values are shown redacted; rotate anything real and move it to a secret manager.", evidence: r.secrets.slice(0, 8).map((s) => `${s.file}:${s.line} — ${s.label}: ${s.redacted}`), basis: "heuristic" }] : []),
      ...vuln.map((d) => ({ id: `osv.${d.name}`, severity: worstSeverity(d.advisories), title: `${d.name}@${d.version}: ${d.advisories.length} advisor${d.advisories.length === 1 ? "y" : "ies"}`, detail: d.advisories[0]?.summary ?? "", evidence: d.advisories.map((a) => `${a.id}${a.cvss ? ` CVSS ${a.cvss}` : ""}${a.fixedIn ? ` — fixed in ${a.fixedIn}` : ""}`), basis: "structure" })),
    ];
    return { vulnerable: vuln, worst: w, findings: f };
  }, [r]);

  return (
    <div className="flex flex-col gap-4">
      <section className="panel panel-ticks animate-rise">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-3 border-b border-line-1 p-[var(--panel-pad)]">
          <div className="min-w-0 flex-1">
            <div className="label mb-1">Code security · {r.durationMs} ms</div>
            <h2 className="display text-xl text-fg-1">{r.files.toLocaleString()} files scanned</h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-fg-3">
              <span>{formatBytes(r.bytes)}</span>
              <span>{r.manifests.length} manifest{r.manifests.length === 1 ? "" : "s"}</span>
              {r.osvQueried > 0 && <span>{r.osvQueried} packages queried against OSV.dev</span>}
            </div>
          </div>
          <div className="flex gap-2">
            <button type="button" className="btn" onClick={() => downloadJson("code-security-report.json", r)}>
              <Download size={14} /> Report
            </button>
            <button type="button" className="btn btn-ghost" onClick={reset}>
              <RotateCcw size={14} /> Another folder
            </button>
          </div>
        </div>
        <div className="grid gap-px bg-line-1 sm:grid-cols-2 xl:grid-cols-4">
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Highest finding" value={worst ? <span style={{ color: SEVERITY_COLOR[worst] }}>{worst[0] + worst.slice(1).toLowerCase()}</span> : "None"} sub={`${findings.length} findings`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Dependencies" value={<span className="tabular">{r.dependencies.length.toLocaleString()}</span>} sub={`${vulnerable.length} with known advisories`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Secrets" value={<span className="tabular">{r.secrets.length}</span>} sub={`${r.secrets.filter((s) => s.confidence === "high").length} high-confidence`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="IaC findings" value={<span className="tabular">{r.iac.length}</span>} sub="Dockerfiles, compose, Kubernetes, Terraform, Actions" />
          </div>
        </div>
        {r.osvErrors.length > 0 && (
          <div className="border-t border-line-1 px-[var(--panel-pad)] py-2 text-xs text-warn">{r.osvErrors[0]}</div>
        )}
      </section>

      <section className="panel">
        <LocalFindings findings={findings} empty="No manifests, secrets or infrastructure files with findings were found in this folder." />
      </section>

      {r.dependencies.length > 0 && (
        <section className="panel">
          <h3 className="label px-[var(--panel-pad)] pt-3">Dependencies</h3>
          <DataTable
            rows={r.dependencies}
            columns={[
              { key: "n", label: "Package", render: (d) => <Mono className="text-fg-1">{d.name}</Mono>, sort: (d) => d.name },
              { key: "v", label: "Version", render: (d) => <Mono>{d.version}</Mono> },
              { key: "e", label: "Ecosystem", render: (d) => <Chip>{d.ecosystem}</Chip> },
              { key: "f", label: "File", render: (d) => <span className="text-xs text-fg-3">{d.file}</span> },
              {
                key: "a",
                label: "Advisories",
                render: (d) =>
                  d.advisories.length ? (
                    <span className="flex flex-wrap gap-1.5">
                      {d.advisories.slice(0, 4).map((a) => (
                        <a key={a.id} href={a.references[0] ?? `https://osv.dev/vulnerability/${a.id}`} target="_blank" rel="noopener noreferrer nofollow" title={a.summary}>
                          <Chip tone={a.severity === "CRITICAL" || a.severity === "HIGH" ? "err" : a.severity === "MEDIUM" ? "warn" : "neutral"}>{a.id}</Chip>
                        </a>
                      ))}
                      {d.advisories.length > 4 && <span className="text-xs text-fg-4">+{d.advisories.length - 4}</span>}
                    </span>
                  ) : (
                    <span className="text-xs text-fg-4">none</span>
                  ),
                sort: (d) => worstSeverity(d.advisories),
              },
              { key: "fx", label: "Fix", render: (d) => (d.advisories.find((a) => a.fixedIn) ? <Mono className="text-ok">{d.advisories.find((a) => a.fixedIn)!.fixedIn}</Mono> : "") },
            ]}
          />
        </section>
      )}

      {r.manifests.some((m) => m.warnings.length) && (
        <section className="panel p-[var(--panel-pad)] text-xs text-fg-3">
          {r.manifests
            .filter((m) => m.warnings.length)
            .map((m) => (
              <p key={m.file}>
                <Mono className="text-fg-2">{m.file}</Mono>: {m.warnings.join("; ")}
              </p>
            ))}
        </section>
      )}
    </div>
  );
}

