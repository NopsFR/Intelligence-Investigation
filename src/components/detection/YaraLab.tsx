"use client";

import { ChevronRight, FileUp, Play, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { parsePe } from "@/lib/analysis/pe";
import { tokenizeYara } from "@/lib/detection/highlight";
import { YARA_EXAMPLES } from "@/lib/detection/samples";
import { YaraError, compileYara, scanYara, type ScanResult, type StringMatch } from "@/lib/detection/yara";
import { cx } from "@/lib/client/cx";
import { EmptyState, ErrorNote } from "@/components/ui/primitives";
import { CodeEditor, FileDrop, HexView, formatBytes, type HexHighlight } from "@/components/ui/workbench";
import { Chip, Mono } from "../analysis/common";

const DEFAULT_RULE = YARA_EXAMPLES[0].source;

type Target = { name: string; bytes: Uint8Array } | null;

export function YaraLab() {
  const [source, setSource] = useState(DEFAULT_RULE);
  const [target, setTarget] = useState<Target>(null);
  const [focus, setFocus] = useState<{ ruleId: string; offset: number } | null>(null);
  const [tab, setTab] = useState<"editor" | "hex">("editor");

  const compiled = useMemo(() => {
    try {
      return { ok: true as const, rules: compileYara(source) };
    } catch (err) {
      return { ok: false as const, error: err instanceof YaraError ? err : new YaraError(err instanceof Error ? err.message : String(err), 1, 1) };
    }
  }, [source]);

  const pe = useMemo(() => {
    if (!target) return null;
    try {
      return parsePe(target.bytes);
    } catch {
      return null;
    }
  }, [target]);

  const result: ScanResult | null = useMemo(() => {
    if (!compiled.ok || !target) return null;
    try {
      return scanYara(compiled.rules, target.bytes, { pe });
    } catch (err) {
      return { results: [], durationMs: 0, bytesScanned: target.bytes.length, warnings: [err instanceof Error ? err.message : String(err)] };
    }
  }, [compiled, target, pe]);

  const highlights: HexHighlight[] = useMemo(() => {
    if (!result || !focus) return [];
    const rule = result.results.find((r) => r.rule === focus.ruleId);
    const out: HexHighlight[] = [];
    for (const s of rule?.strings ?? []) for (const m of s.matches) out.push({ start: m.offset, end: m.offset + m.length, label: `$${s.id}`, color: m.offset === focus.offset ? "var(--color-signal-hi)" : "var(--color-ice)" });
    return out;
  }, [result, focus]);

  const errorLines = compiled.ok ? [] : [{ line: compiled.error.line, message: compiled.error.message }];
  const matchedCount = result?.results.filter((r) => r.matched && !r.isPrivate).length ?? 0;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)]">
      <section className="panel panel-ticks flex flex-col">
        <header className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
          <h2 className="label text-fg-2">Rule</h2>
          <select
            className="input h-7 w-auto text-xs"
            aria-label="Load an example rule"
            defaultValue=""
            onChange={(e) => {
              const ex = YARA_EXAMPLES.find((x) => x.id === e.target.value);
              if (ex) setSource(ex.source);
              e.target.value = "";
            }}
          >
            <option value="" disabled>
              Load an example…
            </option>
            {YARA_EXAMPLES.map((ex) => (
              <option key={ex.id} value={ex.id}>
                {ex.label}
              </option>
            ))}
          </select>
          <span className="ml-auto flex items-center gap-1.5 text-xs">
            {compiled.ok ? (
              <span className="text-ok">
                {compiled.rules.rules.length} rule{compiled.rules.rules.length === 1 ? "" : "s"} compiled
              </span>
            ) : (
              <span className="text-err">Line {compiled.error.line}: {compiled.error.message}</span>
            )}
          </span>
        </header>
        <div className="p-[var(--panel-pad)]">
          <CodeEditor value={source} onChange={setSource} tokenize={tokenizeYara} label="YARA rule source" minHeight={420} errors={errorLines} placeholder={'rule Example {\n  strings:\n    $a = "text"\n  condition:\n    $a\n}'} />
        </div>
        <div className="mt-auto border-t border-line-1 px-[var(--panel-pad)] py-3">
          <FileDrop
            compact
            onFile={(f, bytes) => {
              setTarget({ name: f.name, bytes });
              setFocus(null);
            }}
            maxBytes={64 * 1024 * 1024}
            title={target ? `Scanning ${target.name}` : "Drop a file to scan"}
            description="Any file — text, script, PE, ELF or Mach-O. pe.* conditions need PE."
          />
        </div>
      </section>

      <section className="panel flex flex-col">
        {!target ? (
          <EmptyState icon={<FileUp size={17} />} title="No target file yet" className="flex-1">
            Load an example rule, or write your own, then drop a file to scan it. Nothing leaves your browser.
          </EmptyState>
        ) : (
          <>
            <header className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
              <Play size={13} className="text-fg-3" />
              <span className="min-w-0 truncate text-sm font-medium text-fg-1">{target.name}</span>
              <span className="mono text-xs text-fg-4">{formatBytes(target.bytes.length)}</span>
              {result && (
                <span className="ml-auto flex items-center gap-2 text-xs text-fg-3">
                  {result.durationMs}ms
                  <Chip tone={matchedCount ? "err" : "ok"}>{matchedCount} rule{matchedCount === 1 ? "" : "s"} matched</Chip>
                </span>
              )}
            </header>
            {result && result.warnings.length > 0 && (
              <ErrorNote title="Some rules could not be evaluated">
                <ul className="list-disc pl-4">
                  {result.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </ErrorNote>
            )}
            <div className="flex border-b border-line-1 px-2">
              {(["editor", "hex"] as const).map((t) => (
                <button key={t} type="button" onClick={() => setTab(t)} className={cx("relative px-3 py-2 text-sm font-medium transition-colors", tab === t ? "text-fg-1" : "text-fg-3 hover:text-fg-1")}>
                  {t === "editor" ? "Rule matches" : "Hex"}
                  {tab === t && <span aria-hidden className="absolute bottom-0 left-0 h-[2px] w-full bg-signal" />}
                </button>
              ))}
            </div>
            {tab === "hex" ? (
              <div className="p-3">
                <HexView bytes={target.bytes} height={480} highlights={highlights} focus={focus?.offset} />
              </div>
            ) : (
              <div className="flex-1 overflow-auto">
                {!result?.results.length ? (
                  <EmptyState title="No rules to run">Fix the compile error to scan.</EmptyState>
                ) : (
                  <ul className="divide-y divide-line-1">
                    {result.results
                      .filter((r) => !r.isPrivate)
                      .map((r) => (
                        <RuleRow key={r.rule} result={r} onFocus={(offset) => { setFocus({ ruleId: r.rule, offset }); setTab("hex"); }} />
                      ))}
                  </ul>
                )}
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}

function RuleRow({ result, onFocus }: { result: ScanResult["results"][number]; onFocus: (offset: number) => void }) {
  const [open, setOpen] = useState(result.matched);
  const totalMatches = result.strings.reduce((n, s) => n + s.matches.length, 0);
  return (
    <li>
      <button type="button" onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left hover:bg-ink-2" aria-expanded={open}>
        <ChevronRight size={13} className={cx("shrink-0 text-fg-4 transition-transform", open && "rotate-90")} />
        <span className={cx("h-2 w-2 shrink-0 rounded-full", result.matched ? "bg-err" : "bg-line-3")} aria-hidden />
        <span className={cx("mono text-sm", result.matched ? "font-semibold text-fg-1" : "text-fg-3")}>{result.rule}</span>
        {result.tags.map((t) => (
          <Chip key={t}>{t}</Chip>
        ))}
        {result.meta.attack && <Chip tone="warn">{String(result.meta.attack)}</Chip>}
        <span className="ml-auto text-xs text-fg-4">{result.matched ? `${totalMatches} string match${totalMatches === 1 ? "" : "es"}` : "no match"}</span>
      </button>
      {open && (
        <div className="flex flex-col gap-2 px-3 pb-3 pl-[38px]">
          {result.meta.description && <p className="text-xs text-fg-3">{String(result.meta.description)}</p>}
          {result.strings.map((s) => (
            <div key={s.id} className="flex flex-wrap items-center gap-1.5">
              <Mono className="text-fg-2">${s.id}</Mono>
              {!s.matches.length ? (
                <span className="text-xs text-fg-4">no match</span>
              ) : (
                <>
                  <span className="text-xs text-fg-4">×{s.matches.length}</span>
                  {s.matches.slice(0, 8).map((m: StringMatch, i) => (
                    <button key={i} type="button" onClick={() => onFocus(m.offset)} className="mono link text-[11px]">
                      0x{m.offset.toString(16)}
                    </button>
                  ))}
                  {s.truncated && <span className="text-xs text-fg-4">truncated at 10,000</span>}
                </>
              )}
            </div>
          ))}
          {!result.strings.length && (
            <p className="flex items-center gap-1.5 text-xs text-fg-3">
              <Sparkles size={12} /> Condition-only rule (no strings section).
            </p>
          )}
        </div>
      )}
    </li>
  );
}


