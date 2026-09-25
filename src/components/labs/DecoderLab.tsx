"use client";

import { ArrowRight, Redo2, RotateCcw, Sparkles, Undo2 } from "lucide-react";
import { useMemo, useState } from "react";
import { detectCandidates, type DecodeCandidate } from "@/lib/labs/decoder";
import { useInvestigate } from "@/lib/client/investigate";
import { CopyButton, EmptyState } from "@/components/ui/primitives";
import { Chip, Mono } from "../analysis/common";

interface HistoryEntry {
  text: string;
  appliedLabel?: string;
}

export function DecoderLab() {
  const [history, setHistory] = useState<HistoryEntry[]>([{ text: "" }]);
  const [cursor, setCursor] = useState(0);
  const { start, pending } = useInvestigate();
  const current = history[cursor];
  const candidates = useMemo(() => detectCandidates(current.text), [current.text]);

  const setInput = (text: string) => {
    setHistory([{ text }]);
    setCursor(0);
  };

  const apply = (c: DecodeCandidate) => {
    const output = c.apply(current.text);
    const truncated = history.slice(0, cursor + 1);
    setHistory([...truncated, { text: output, appliedLabel: c.label }]);
    setCursor(truncated.length);
  };

  const canUndo = cursor > 0;
  const canRedo = cursor < history.length - 1;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <section className="panel panel-ticks flex flex-col">
        <header className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
          <h2 className="label text-fg-2">Chain</h2>
          <div className="ml-auto flex items-center gap-1">
            <button type="button" className="btn btn-ghost btn-sm" disabled={!canUndo} onClick={() => setCursor((c) => c - 1)}>
              <Undo2 size={13} /> Undo
            </button>
            <button type="button" className="btn btn-ghost btn-sm" disabled={!canRedo} onClick={() => setCursor((c) => c + 1)}>
              <Redo2 size={13} /> Redo
            </button>
            <button type="button" className="btn btn-ghost btn-sm" disabled={history.length === 1} onClick={() => setInput("")}>
              <RotateCcw size={13} /> Clear
            </button>
          </div>
        </header>
        {history.length > 1 && (
          <ol className="flex flex-wrap items-center gap-1.5 border-b border-line-1 px-[var(--panel-pad)] py-2 text-xs">
            {history.map((h, i) => (
              <li key={i} className="flex items-center gap-1.5">
                {i > 0 && <ArrowRight size={11} className="text-fg-4" />}
                <button type="button" onClick={() => setCursor(i)} className={i === cursor ? "font-medium text-fg-1" : "text-fg-4 hover:text-fg-2"}>
                  {i === 0 ? "input" : h.appliedLabel?.split(" ")[0]}
                </button>
              </li>
            ))}
          </ol>
        )}
        <div className="p-[var(--panel-pad)]">
          <textarea className="input mono min-h-[220px] text-[12.5px]" placeholder="Paste text, then apply a detected transform…" value={current.text} onChange={(e) => setInput(e.target.value)} aria-label="Decoder input" spellCheck={false} />
        </div>
        {current.text && (
          <div className="flex items-center gap-2 border-t border-line-1 px-[var(--panel-pad)] py-2.5">
            <CopyButton value={current.text} label="Copy current text" />
            <button type="button" className="btn btn-ghost btn-sm" disabled={pending} onClick={() => void start(current.text, "QUICK")}>
              Investigate this value
            </button>
          </div>
        )}
      </section>

      <section className="panel">
        <header className="border-b border-line-1 px-[var(--panel-pad)] py-2.5">
          <h2 className="label text-fg-2">Detected transforms</h2>
        </header>
        {!candidates.length ? (
          <EmptyState icon={<Sparkles size={17} />} title="Nothing detected" className="px-4 py-8">
            Paste base64, hex, binary, URL-encoded, HTML-entity, \\u-escaped or JWT text.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-line-1">
            {candidates.map((c) => (
              <li key={c.id}>
                <button type="button" onClick={() => apply(c)} className="flex w-full items-start gap-2.5 px-[var(--panel-pad)] py-3 text-left hover:bg-ink-2">
                  <Chip tone={c.confidence === "high" ? "ok" : c.confidence === "medium" ? "warn" : "neutral"}>{c.confidence}</Chip>
                  <span className="min-w-0 flex-1 text-sm text-fg-1">{c.label}</span>
                  <ArrowRight size={13} className="mt-0.5 shrink-0 text-fg-4" />
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-4">Every step runs in your browser. ROT13 and reverse are always offered since they cannot be reliably auto-detected.</p>
      </section>

      {history.length > 1 && (
        <section className="panel xl:col-span-2">
          <header className="border-b border-line-1 px-[var(--panel-pad)] py-2.5">
            <h2 className="label text-fg-2">Steps</h2>
          </header>
          <ol className="flex flex-col divide-y divide-line-1">
            {history.map((h, i) => (
              <li key={i} className="flex items-start gap-3 px-[var(--panel-pad)] py-2.5">
                <span className="mono w-16 shrink-0 text-xs text-fg-4">{i === 0 ? "input" : h.appliedLabel}</span>
                <Mono className="min-w-0 flex-1 break-all whitespace-pre-wrap text-fg-2">{h.text.slice(0, 400)}{h.text.length > 400 ? "…" : ""}</Mono>
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  );
}
