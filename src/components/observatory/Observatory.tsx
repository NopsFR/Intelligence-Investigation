"use client";

import { ChevronRight, ExternalLink, KeyRound, Loader2, PlugZap, RefreshCw, Search } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { CATEGORY_LABELS, OBSERVABLE_SHORT, type ObservableType, type ProviderCategory } from "@/lib/core/types";
import type { CheckResult, ConnectionState, ProviderSnapshot } from "@/lib/db/health";
import { api, type ApiClientError } from "@/lib/client/api";
import { cx } from "@/lib/client/cx";
import { duration } from "@/lib/client/format";
import { Prov } from "@/components/ui/badges";
import { useToast } from "@/components/ui/overlays";
import { EmptyState } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";

export const STATE_META: Record<ConnectionState, { label: string; color: string; glyph: string }> = {
  CONNECTED: { label: "Connected", color: "var(--color-ok)", glyph: "●" },
  NOT_CONFIGURED: { label: "Not configured", color: "var(--color-fg-4)", glyph: "○" },
  AUTH_FAILED: { label: "Authentication failed", color: "var(--color-err)", glyph: "×" },
  RATE_LIMITED: { label: "Rate limited", color: "var(--color-warn)", glyph: "!" },
  TIMEOUT: { label: "Timeout", color: "var(--color-warn)", glyph: "!" },
  UNAVAILABLE: { label: "Unavailable", color: "var(--color-err)", glyph: "×" },
  ERROR: { label: "Error", color: "var(--color-err)", glyph: "×" },
  UNTESTED: { label: "Not tested", color: "var(--color-fg-3)", glyph: "◌" },
  LOCAL: { label: "Local analyser", color: "var(--color-fg-3)", glyph: "◆" },
};

function StateLabel({ state, testing }: { state: ConnectionState; testing?: boolean }) {
  if (testing) {
    return (
      <span className="inline-flex items-center gap-2 text-xs text-ice">
        <span className="dot dot-live" />
        Testing…
      </span>
    );
  }
  const m = STATE_META[state];
  return (
    <span key={state} className="inline-flex animate-fade items-center gap-2 text-xs whitespace-nowrap" style={{ color: state === "CONNECTED" ? "var(--color-fg-1)" : m.color }}>
      <span aria-hidden className="mono w-[10px] text-center text-[11px] leading-none" style={{ color: m.color }}>
        {m.glyph}
      </span>
      {m.label}
    </span>
  );
}

/** Latency history of real connection tests, oldest → newest. */
function CheckHistory({ checks }: { checks: ProviderSnapshot["checks"] }) {
  const series = [...checks].reverse();
  if (!series.length) return <span className="text-xs text-fg-4">No tests yet</span>;
  const max = Math.max(1, ...series.map((c) => c.latencyMs ?? 0));
  return (
    <div className="flex h-[28px] items-end gap-[2px]" role="img" aria-label={`Last ${series.length} tests`}>
      {series.map((c, i) => {
        const ok = ["SUCCESS", "PARTIAL", "EMPTY"].includes(c.status);
        return <span key={i} title={`${c.at} · ${c.status} · ${c.latencyMs ?? "?"} ms`} className="w-[5px] rounded-[1px]" style={{ height: `${Math.max(12, ((c.latencyMs ?? 0) / max) * 100)}%`, background: ok ? "var(--color-fg-3)" : "var(--color-err)" }} />;
      })}
    </div>
  );
}

function Detail({ p }: { p: ProviderSnapshot }) {
  return (
    <div className="grid gap-5 bg-ink-0 px-5 py-4 lg:grid-cols-3">
      <div className="flex flex-col gap-3">
        <p className="text-sm text-fg-2">{p.description}</p>
        <dl className="mono grid grid-cols-[92px_1fr] gap-y-1 text-[11px]">
          <dt className="text-fg-4">endpoint</dt>
          <dd className="break-all text-fg-2">{p.endpoint}</dd>
          <dt className="text-fg-4">timeout</dt>
          <dd className="text-fg-2">{duration(p.timeoutMs)}</dd>
          <dt className="text-fg-4">cache</dt>
          <dd className="text-fg-2">{p.cacheTtlSeconds ? `${Math.round(p.cacheTtlSeconds / 60)} min` : "not cached"}</dd>
          <dt className="text-fg-4">supports</dt>
          <dd className="font-sans text-fg-2">{p.supports.map((s) => OBSERVABLE_SHORT[s as ObservableType]).join(" · ")}</dd>
          {p.healthCheck && (
            <>
              <dt className="text-fg-4">test uses</dt>
              <dd className="text-fg-2">{p.healthCheck.observable}</dd>
            </>
          )}
        </dl>
        <div className="flex flex-wrap gap-2">
          <a href={p.homepage} target="_blank" rel="noopener noreferrer" className="btn btn-ghost btn-sm">
            Homepage <ExternalLink size={11} />
          </a>
          {p.docs && (
            <a href={p.docs} target="_blank" rel="noopener noreferrer" className="btn btn-ghost btn-sm">
              API docs <ExternalLink size={11} />
            </a>
          )}
        </div>
      </div>
      <div className="flex flex-col gap-3">
        <div>
          <div className="label mb-1.5">Authentication</div>
          {p.auth.type === "none" ? (
            <p className="text-xs text-fg-2">No credentials required.</p>
          ) : (
            <div className="text-xs text-fg-2">
              <p>
                {p.auth.type === "required" ? "API key required." : "Optional API key."} {p.auth.benefit}
              </p>
              <p className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <KeyRound size={11} className="text-fg-3" />
                {p.auth.env?.map((e) => (
                  <code key={e} className="mono rounded-[2px] bg-ink-2 px-1.5 text-[11px] text-fg-1">
                    {e}
                  </code>
                ))}
                <span className={p.auth.keyPresent ? "text-ok" : "text-fg-4"}>{p.auth.keyPresent ? "set (value hidden)" : "not set"}</span>
              </p>
              {p.auth.signup && (
                <a href={p.auth.signup} target="_blank" rel="noopener noreferrer" className="link mt-1.5 inline-flex items-center gap-1">
                  Get a key <ExternalLink size={10} />
                </a>
              )}
            </div>
          )}
        </div>
        {(p.limits || p.terms) && (
          <div>
            <div className="label mb-1.5">Limits & terms</div>
            {p.limits && <p className="text-xs text-fg-2">{p.limits}</p>}
            {p.terms && <p className="mt-1 text-xs text-fg-3">{p.terms}</p>}
          </div>
        )}
        {p.quotas.length > 0 && (
          <div>
            <div className="label mb-1.5">Local request budget</div>
            <ul className="flex flex-col gap-1.5">
              {p.quotas.map((q) => (
                <li key={q.label} className="text-xs">
                  <div className="flex justify-between text-fg-3">
                    <span>{q.label}</span>
                    <span className="mono tabular">
                      {q.used}/{q.limit}
                    </span>
                  </div>
                  <div className="mt-1 h-[3px] rounded-[1px] bg-ink-3">
                    <div className="h-full rounded-[1px] transition-[width] duration-500" style={{ width: `${Math.min(100, (q.used / q.limit) * 100)}%`, background: q.used >= q.limit ? "var(--color-warn)" : "var(--color-fg-3)" }} />
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      <div className="flex flex-col gap-3">
        <div>
          <div className="label mb-1.5">Connection tests</div>
          <CheckHistory checks={p.checks} />
        </div>
        {p.lastCheck && (
          <div className="text-xs">
            <div className="label mb-1.5">Last test</div>
            <p className="text-fg-2">
              <Time iso={p.lastCheck.at} mode="both" /> · {p.lastCheck.latencyMs !== undefined ? duration(p.lastCheck.latencyMs) : "—"}
            </p>
            {p.lastCheck.message && (
              <p className="mt-1.5 rounded-[2px] border-l-2 border-err bg-ink-2 px-2 py-1.5 text-fg-2">
                {p.lastCheck.errorType && <span className="mono mr-1.5 text-[10.5px] text-err">{p.lastCheck.errorType}</span>}
                {p.lastCheck.message}
              </p>
            )}
          </div>
        )}
        <div className="text-xs">
          <div className="label mb-1.5">Investigations · 24 h</div>
          {p.usage.total ? (
            <dl className="grid grid-cols-2 gap-y-1 text-fg-2">
              <dt className="text-fg-4">calls</dt>
              <dd className="mono tabular">{p.usage.total}</dd>
              <dt className="text-fg-4">answered</dt>
              <dd className="mono tabular">{p.usage.answered}</dd>
              <dt className="text-fg-4">failed</dt>
              <dd className={cx("mono tabular", p.usage.failed > 0 && "text-warn")}>{p.usage.failed}</dd>
              <dt className="text-fg-4">served from cache</dt>
              <dd className="mono tabular">{p.usage.cached}</dd>
              {Object.entries(p.usage.byStatus).map(([k, v]) => (
                <Fragment key={k}>
                  <dt className="mono text-[10.5px] text-fg-4">{k}</dt>
                  <dd className="mono tabular text-[11px]">{v}</dd>
                </Fragment>
              ))}
            </dl>
          ) : (
            <p className="text-fg-4">Not used in the last 24 hours.</p>
          )}
        </div>
      </div>
    </div>
  );
}

export function Observatory({ initial }: { initial: { providers: ProviderSnapshot[]; generatedAt: string } }) {
  const [snapshot, setSnapshot] = useState(initial);
  const [testing, setTesting] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [state, setState] = useState<ConnectionState | "ALL">("ALL");
  const [kind, setKind] = useState<"all" | "external" | "native" | "derived">("external");
  const [refreshing, setRefreshing] = useState(false);
  const [testingAll, setTestingAll] = useState(false);
  const toast = useToast();

  const refresh = async () => {
    setRefreshing(true);
    try {
      setSnapshot(await api("/api/observatory"));
    } finally {
      setRefreshing(false);
    }
  };

  const test = async (id: string) => {
    setTesting((s) => new Set(s).add(id));
    try {
      const r = await api<CheckResult>(`/api/observatory/${id}/test`, { method: "POST" });
      const p = snapshot.providers.find((x) => x.id === id);
      toast({ kind: r.state === "CONNECTED" ? "success" : "error", title: `${p?.name ?? id}: ${STATE_META[r.state].label}`, body: `${r.message} · ${duration(r.latencyMs)}` });
      await refresh();
    } catch (e) {
      toast({ kind: "error", title: "Test could not run", body: (e as ApiClientError).message });
    } finally {
      setTesting((s) => {
        const n = new Set(s);
        n.delete(id);
        return n;
      });
    }
  };

  const testAll = async () => {
    const ids = snapshot.providers.filter((p) => p.testable && p.configured).map((p) => p.id);
    setTestingAll(true);
    setTesting(new Set(ids));
    try {
      const r = await api<{ results: CheckResult[]; skipped: string[] }>("/api/observatory/test-all", { method: "POST" });
      const ok = r.results.filter((x) => x.state === "CONNECTED").length;
      toast({ kind: ok === r.results.length ? "success" : "info", title: `${ok} of ${r.results.length} sources connected`, body: r.skipped.length ? `${r.skipped.length} need an API key and were not called.` : undefined });
      await refresh();
    } catch (e) {
      toast({ kind: "error", title: "Could not test all sources", body: (e as ApiClientError).message });
    } finally {
      setTestingAll(false);
      setTesting(new Set());
    }
  };

  const scoped = snapshot.providers.filter((p) => kind === "all" || p.kind === kind);
  const counts = useMemo(() => {
    const c: Partial<Record<ConnectionState, number>> = {};
    for (const p of scoped) c[p.state] = (c[p.state] ?? 0) + 1;
    return c;
  }, [scoped]);
  const shown = scoped.filter((p) => (state === "ALL" || p.state === state) && (!q || `${p.name} ${p.vendor} ${p.id} ${p.category}`.toLowerCase().includes(q.toLowerCase())));

  return (
    <div className="flex flex-col gap-4">
      <div className="panel panel-ticks p-[var(--panel-pad)]">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <div className="flex h-[8px] min-w-[240px] flex-1 overflow-hidden rounded-[1px] bg-ink-3" aria-hidden>
            {(Object.keys(STATE_META) as ConnectionState[]).map((s) =>
              counts[s] ? <div key={s} className="h-full border-r border-ink-1 transition-[width] duration-500" style={{ width: `${(counts[s]! / scoped.length) * 100}%`, background: STATE_META[s].color, opacity: s === "NOT_CONFIGURED" || s === "LOCAL" ? 0.45 : 0.9 }} /> : null
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-fg-4">
              Snapshot <Time iso={snapshot.generatedAt} />
            </span>
            <button type="button" className="btn btn-ghost btn-sm btn-icon" onClick={() => void refresh()} aria-label="Refresh" disabled={refreshing}>
              <RefreshCw size={13} className={cx(refreshing && "animate-spin")} />
            </button>
            <button type="button" className="btn btn-sm" onClick={() => void testAll()} disabled={testingAll}>
              {testingAll ? <Loader2 size={13} className="animate-spin" /> : <PlugZap size={13} />} Test all configured
            </button>
          </div>
        </div>
        <div role="radiogroup" aria-label="Filter by state" className="mt-3 flex flex-wrap gap-1">
          <button type="button" role="radio" aria-checked={state === "ALL"} onClick={() => setState("ALL")} className={cx("inline-flex h-[26px] items-center gap-1.5 rounded-[2px] border px-2 text-xs", state === "ALL" ? "border-line-3 bg-ink-3 text-fg-1" : "border-transparent text-fg-3 hover:text-fg-1")}>
            All <span className="mono text-[10.5px] text-fg-4">{scoped.length}</span>
          </button>
          {(Object.keys(STATE_META) as ConnectionState[])
            .filter((s) => counts[s])
            .map((s) => (
              <button key={s} type="button" role="radio" aria-checked={state === s} onClick={() => setState(s)} className={cx("inline-flex h-[26px] items-center gap-1.5 rounded-[2px] border px-2 text-xs", state === s ? "border-line-3 bg-ink-3 text-fg-1" : "border-transparent text-fg-3 hover:text-fg-1")}>
                <span aria-hidden style={{ color: STATE_META[s].color }}>
                  {STATE_META[s].glyph}
                </span>
                {STATE_META[s].label}
                <span className="mono text-[10.5px] text-fg-4">{counts[s]}</span>
              </button>
            ))}
        </div>
      </div>

      <div className="panel panel-ticks">
        <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
          <label className="relative min-w-[200px] flex-1 sm:max-w-[300px]">
            <span className="sr-only">Search sources</span>
            <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-fg-4" />
            <input className="input h-[30px] pl-8 text-xs" placeholder="Search sources" value={q} onChange={(e) => setQ(e.target.value)} />
          </label>
          <div role="radiogroup" aria-label="Source kind" className="inline-flex rounded-[3px] border border-line-2 bg-ink-0 p-[2px]">
            {(["external", "native", "derived", "all"] as const).map((k) => (
              <button key={k} type="button" role="radio" aria-checked={kind === k} onClick={() => setKind(k)} className={cx("h-[24px] rounded-[2px] px-2.5 text-xs capitalize", kind === k ? "bg-ink-3 text-fg-1" : "text-fg-3 hover:text-fg-1")}>
                {k === "external" ? "External APIs" : k}
              </button>
            ))}
          </div>
        </div>
        {shown.length ? (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th className="w-[26px]" />
                  <th>Source</th>
                  <th className="hidden md:table-cell">Category</th>
                  <th>Auth</th>
                  <th>State</th>
                  <th className="text-right">Last test</th>
                  <th className="hidden text-right lg:table-cell">p95 · 24h</th>
                  <th className="hidden text-right xl:table-cell">Calls · 24h</th>
                  <th className="w-[92px]" />
                </tr>
              </thead>
              <tbody>
                {shown.map((p) => {
                  const open = expanded === p.id;
                  return (
                    <Fragment key={p.id}>
                      <tr className="cursor-pointer" data-selected={open || undefined} onClick={(e) => !(e.target as HTMLElement).closest("button") && setExpanded(open ? null : p.id)}>
                        <td className="align-middle">
                          <button type="button" className="text-fg-4 hover:text-fg-1" aria-expanded={open} aria-label={`${open ? "Collapse" : "Expand"} ${p.name}`} onClick={() => setExpanded(open ? null : p.id)}>
                            <ChevronRight size={13} className={cx("transition-transform duration-200", open && "rotate-90")} />
                          </button>
                        </td>
                        <td>
                          <div className="flex items-center gap-2.5">
                            <Prov id={p.id} className="w-[38px] justify-center" />
                            <div className="min-w-0">
                              <div className="truncate text-sm text-fg-1">{p.name}</div>
                              <div className="truncate text-2xs text-fg-4">
                                {p.vendor}
                                {p.active && " · contacts targets"}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="hidden align-middle text-xs text-fg-3 md:table-cell">{CATEGORY_LABELS[p.category as ProviderCategory] ?? p.category}</td>
                        <td className="align-middle text-xs">
                          {p.auth.type === "none" ? <span className="text-fg-4">None</span> : p.auth.keyPresent ? <span className="text-fg-2">Key set</span> : <span className={p.auth.type === "required" ? "text-fg-3" : "text-fg-4"}>{p.auth.type === "required" ? "Key required" : "Optional key"}</span>}
                        </td>
                        <td className="align-middle">
                          <StateLabel state={p.state} testing={testing.has(p.id)} />
                        </td>
                        <td className="mono tabular text-right align-middle text-[11px] text-fg-3">
                          {p.lastCheck ? (
                            <>
                              {p.lastCheck.latencyMs !== undefined ? duration(p.lastCheck.latencyMs) : ""}
                              <span className="ml-2 font-sans text-fg-4">
                                <Time iso={p.lastCheck.at} />
                              </span>
                            </>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="mono tabular hidden text-right align-middle text-[11px] text-fg-3 lg:table-cell">{p.usage.p95LatencyMs !== undefined ? duration(p.usage.p95LatencyMs) : "—"}</td>
                        <td className="mono tabular hidden text-right align-middle text-[11px] text-fg-3 xl:table-cell">
                          {p.usage.total ? (
                            <>
                              {p.usage.total}
                              {p.usage.failed > 0 && <span className="text-warn"> · {p.usage.failed}✕</span>}
                            </>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="text-right align-middle">
                          {p.testable && (
                            <button type="button" className="btn btn-sm" disabled={testing.has(p.id) || !p.configured} title={p.configured ? "Run a real request" : "Configure an API key first"} onClick={() => void test(p.id)}>
                              {testing.has(p.id) ? <Loader2 size={12} className="animate-spin" /> : <PlugZap size={12} />} Test
                            </button>
                          )}
                        </td>
                      </tr>
                      {open && (
                        <tr className="hover:!bg-transparent">
                          <td colSpan={9} className="!p-0">
                            <div className="animate-fade">
                              <Detail p={p} />
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No sources match">Adjust the search or state filter.</EmptyState>
        )}
      </div>
    </div>
  );
}
