"use client";

import { ChevronRight, ListChecks, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { tokenizeYaml } from "@/lib/detection/highlight";
import { SIGMA_EXAMPLES, SYNTHETIC_EVENTS } from "@/lib/detection/samples";
import { BACKENDS, SigmaError, convertSigma, evaluateSigma, parseEvents, parseSigma, type Backend, type SigmaMatch } from "@/lib/detection/sigma";
import { cx } from "@/lib/client/cx";
import { CopyButton, EmptyState } from "@/components/ui/primitives";
import { CodeEditor } from "@/components/ui/workbench";
import { AttackChip, Chip, Mono } from "../analysis/common";

const DEFAULT_RULE = SIGMA_EXAMPLES[0].source;

export function SigmaLab() {
  const [source, setSource] = useState(DEFAULT_RULE);
  const [eventText, setEventText] = useState(SYNTHETIC_EVENTS);
  const [backend, setBackend] = useState<Backend>("splunk");
  const [tab, setTab] = useState<"matches" | "query">("matches");

  const parsed = useMemo(() => {
    try {
      const rules = parseSigma(source);
      return { ok: true as const, rule: rules[0], extra: rules.length - 1 };
    } catch (err) {
      return { ok: false as const, error: err instanceof SigmaError ? err : new SigmaError(err instanceof Error ? err.message : String(err)) };
    }
  }, [source]);

  const events = useMemo(() => {
    try {
      return { ok: true as const, ...parseEvents(eventText) };
    } catch (err) {
      return { ok: false as const, error: err instanceof Error ? err.message : String(err) };
    }
  }, [eventText]);

  const matches: SigmaMatch[] | null = useMemo(() => {
    if (!parsed.ok || !events.ok) return null;
    try {
      return evaluateSigma(parsed.rule, events.events);
    } catch {
      return null;
    }
  }, [parsed, events]);

  const conversion = useMemo(() => {
    if (!parsed.ok) return null;
    try {
      return convertSigma(parsed.rule, backend);
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  }, [parsed, backend]);

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
              const ex = SIGMA_EXAMPLES.find((x) => x.id === e.target.value);
              if (ex) setSource(ex.source);
              e.target.value = "";
            }}
          >
            <option value="" disabled>
              Load an example…
            </option>
            {SIGMA_EXAMPLES.map((ex) => (
              <option key={ex.id} value={ex.id}>
                {ex.label}
              </option>
            ))}
          </select>
          <span className="ml-auto text-xs">
            {parsed.ok ? <span className="text-ok">Parsed{parsed.extra ? ` (+${parsed.extra} more documents ignored)` : ""}</span> : <span className="text-err">{parsed.error.message}</span>}
          </span>
        </header>
        <div className="p-[var(--panel-pad)]">
          <CodeEditor value={source} onChange={setSource} tokenize={tokenizeYaml} label="Sigma rule source (YAML)" minHeight={340} placeholder={"title: My rule\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: '\\\\cmd.exe'\n  condition: sel"} />
        </div>
        {parsed.ok && (parsed.rule.warnings.length > 0 || parsed.rule.description) && (
          <div className="border-t border-line-1 px-[var(--panel-pad)] py-3">
            {parsed.rule.description && <p className="mb-2 text-sm text-fg-2">{parsed.rule.description}</p>}
            <div className="flex flex-wrap items-center gap-1.5">
              {parsed.rule.level && <Chip tone={parsed.rule.level === "critical" || parsed.rule.level === "high" ? "err" : parsed.rule.level === "medium" ? "warn" : "neutral"}>{parsed.rule.level}</Chip>}
              {parsed.rule.logsource.product && <Chip>{[parsed.rule.logsource.product, parsed.rule.logsource.category, parsed.rule.logsource.service].filter(Boolean).join("/")}</Chip>}
              {parsed.rule.attack.map((a) => (
                <AttackChip key={a} id={a} />
              ))}
            </div>
            {parsed.rule.warnings.length > 0 && (
              <ul className="mt-2 list-disc pl-4 text-xs text-warn">
                {parsed.rule.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        <div className="mt-auto border-t border-line-1 px-[var(--panel-pad)] py-3">
          <div className="mb-1.5 flex items-center justify-between">
            <label htmlFor="sigma-events" className="label">
              Events to evaluate against
            </label>
            <span className="text-xs text-fg-4">{events.ok ? `${events.format} · ${events.events.length} event${events.events.length === 1 ? "" : "s"}` : "could not parse"}</span>
          </div>
          <textarea id="sigma-events" className="input mono h-32 w-full resize-y p-2 text-[11.5px]" spellCheck={false} value={eventText} onChange={(e) => setEventText(e.target.value)} />
          <p className="mt-1.5 text-xs text-fg-4">JSON array, NDJSON, CSV with a header row, or Windows Event XML. The bundled events are fabricated for this demonstration.</p>
        </div>
      </section>

      <section className="panel flex flex-col">
        <div className="flex border-b border-line-1 px-2">
          {(["matches", "query"] as const).map((t) => (
            <button key={t} type="button" onClick={() => setTab(t)} className={cx("relative px-3 py-2 text-sm font-medium transition-colors", tab === t ? "text-fg-1" : "text-fg-3 hover:text-fg-1")}>
              {t === "matches" ? "Matches" : "SIEM query"}
              {tab === t && <span aria-hidden className="absolute bottom-0 left-0 h-[2px] w-full bg-signal" />}
            </button>
          ))}
          {tab === "matches" && matches && (
            <span className="ml-auto self-center pr-2">
              <Chip tone={matches.length ? "err" : "ok"}>
                {matches.length} of {events.ok ? events.events.length : 0} events matched
              </Chip>
            </span>
          )}
        </div>
        {tab === "matches" ? (
          !parsed.ok ? (
            <EmptyState title="Fix the rule to evaluate it" className="flex-1" />
          ) : !events.ok ? (
            <EmptyState title="Could not parse the events" className="flex-1">
              {events.error}
            </EmptyState>
          ) : !matches?.length ? (
            <EmptyState icon={<ListChecks size={17} />} title="No events matched" className="flex-1">
              The condition evaluated against every event and matched none. That is an outcome of running the rule, not an assumption.
            </EmptyState>
          ) : (
            <ul className="flex-1 divide-y divide-line-1 overflow-auto">
              {matches.map((m) => (
                <MatchRow key={m.index} match={m} event={events.events[m.index]} />
              ))}
            </ul>
          )
        ) : (
          <div className="flex flex-1 flex-col">
            <div className="flex items-center gap-1.5 border-b border-line-1 px-3 py-2">
              {BACKENDS.map((b) => (
                <button key={b.id} type="button" className={cx("btn btn-sm", backend === b.id ? "btn-primary" : "btn-ghost")} onClick={() => setBackend(b.id)}>
                  {b.label}
                </button>
              ))}
              {conversion && "query" in conversion && (
                <span className="ml-auto">
                  <CopyButton value={conversion.query} label="Copy query" />
                </span>
              )}
            </div>
            {!parsed.ok ? (
              <EmptyState title="Fix the rule to convert it" className="flex-1" />
            ) : conversion && "error" in conversion ? (
              <div className="p-4 text-sm text-err">{conversion.error}</div>
            ) : (
              <div className="flex-1 overflow-auto p-4">
                <pre className="mono text-[12px] leading-[19px] whitespace-pre-wrap text-fg-1">{conversion?.query}</pre>
                {conversion?.warnings.length ? (
                  <ul className="mt-4 list-disc space-y-1 pl-4 text-xs text-warn">
                    {conversion.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                ) : null}
                <p className="mt-4 flex items-center gap-1.5 text-xs text-fg-4">
                  <Sparkles size={12} /> Field names follow Sigma&apos;s taxonomy — map them to your table or index schema before running.
                </p>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function MatchRow({ match, event }: { match: SigmaMatch; event: unknown }) {
  const [open, setOpen] = useState(false);
  return (
    <li>
      <button type="button" onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left hover:bg-ink-2" aria-expanded={open}>
        <ChevronRight size={13} className={cx("shrink-0 text-fg-4 transition-transform", open && "rotate-90")} />
        <span className="mono text-sm text-fg-1">Event #{match.index + 1}</span>
        <span className="ml-auto text-xs text-fg-4">{match.evidence.length} field{match.evidence.length === 1 ? "" : "s"} matched</span>
      </button>
      {open && (
        <div className="flex flex-col gap-3 px-3 pb-3 pl-[38px]">
          {match.evidence.length > 0 && (
            <ul className="flex flex-col gap-1">
              {match.evidence.map((e, i) => (
                <li key={i} className="text-xs">
                  <Mono className="text-fg-2">{e.search}</Mono>
                  {e.field && (
                    <>
                      {" "}
                      <Mono className="text-fg-1">{e.field}</Mono>
                    </>
                  )}{" "}
                  <span className="text-fg-4">matched</span> <Mono className="text-fg-1">{e.pattern}</Mono>
                  {e.value && (
                    <>
                      {" "}
                      <span className="text-fg-4">in</span> <Mono className="break-all text-fg-2">{e.value.slice(0, 120)}</Mono>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
          <pre className="mono max-h-56 overflow-auto rounded-[2px] bg-ink-0 p-2 text-[11px] text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{JSON.stringify(event, null, 2)}</pre>
        </div>
      )}
    </li>
  );
}
