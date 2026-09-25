"use client";

import { ArrowUpRight, Braces, ChevronRight, Database } from "lucide-react";
import { useEffect, useState } from "react";
import { CATEGORY_LABELS, STATUS_LABELS, type ProviderOutcome } from "@/lib/core/types";
import { api } from "@/lib/client/api";
import { useCatalog } from "@/lib/client/catalog";
import { cx } from "@/lib/client/cx";
import { duration } from "@/lib/client/format";
import type { StepView } from "@/lib/client/investigation";
import { Prov, StatusDot, StatusLabel, statusColor } from "@/components/ui/badges";
import { Drawer } from "@/components/ui/overlays";
import { CopyButton, ErrorNote, Skeleton } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";
import { FactsGrid } from "./Facts";
import { FindingItem } from "./Findings";
import { useWorkspace } from "./context";

/** Segmented progress: one cell per plan step, filled with its state as results land. */
export function ProgressStrip({ steps, className }: { steps: StepView[]; className?: string }) {
  const { name } = useCatalog();
  return (
    <div className={cx("flex h-[6px] gap-[2px]", className)} role="img" aria-label={`${steps.filter((s) => s.outcome).length} of ${steps.length} sources finished`}>
      {steps.map((s) => (
        <span
          key={s.id}
          title={`${name(s.id)}: ${STATUS_LABELS[s.state]}`}
          className={cx("relative min-w-[3px] flex-1 overflow-hidden rounded-[1px] transition-colors duration-500", !s.outcome && "bg-ink-3")}
          style={s.outcome ? { background: statusColor(s.state), opacity: s.state === "SKIPPED" || s.state === "NOT_CONFIGURED" ? 0.35 : s.state === "EMPTY" ? 0.55 : 0.9 } : undefined}
        >
          {s.state === "RUNNING" && <span aria-hidden className="absolute inset-y-0 left-0 w-1/2 animate-scan bg-gradient-to-r from-transparent via-[color-mix(in_srgb,var(--color-ice)_75%,transparent)] to-transparent" />}
        </span>
      ))}
    </div>
  );
}

/** Live list of sources with state transitions (QUEUED → RUNNING → result). */
export function SourcesTable({ steps }: { steps: StepView[] }) {
  const { get } = useCatalog();
  const { openSource } = useWorkspace();
  return (
    <div className="overflow-x-auto">
      <table className="table">
        <thead>
          <tr>
            <th>Source</th>
            <th>State</th>
            <th className="hidden lg:table-cell">Result</th>
            <th className="text-right">Latency</th>
            <th className="hidden text-right md:table-cell">Retrieved</th>
            <th className="w-[28px]" />
          </tr>
        </thead>
        <tbody>
          {steps.map((s) => {
            const meta = get(s.id);
            const o = s.outcome;
            return (
              <tr key={s.id} className={cx(o ? "cursor-pointer" : "opacity-80")} onClick={() => o && openSource(s.id)}>
                <td>
                  <div className="flex items-center gap-2.5">
                    <Prov id={s.id} className="w-[38px] justify-center" />
                    <div className="min-w-0">
                      <div className="truncate text-sm text-fg-1">{meta?.name ?? s.id}</div>
                      <div className="truncate text-2xs text-fg-4">
                        {meta?.vendor}
                        {meta?.active && <span className="ml-1.5 text-fg-3">· contacts target</span>}
                      </div>
                    </div>
                  </div>
                </td>
                <td className="align-middle">
                  <span key={s.state} className="inline-block animate-fade">
                    <StatusLabel state={s.state} />
                  </span>
                  {o?.cached && <span className="label ml-2 text-fg-4">cached</span>}
                </td>
                <td className="hidden max-w-[420px] align-middle lg:table-cell">
                  <span className={cx("line-clamp-2 text-xs", o?.errorMessage && !o.result ? "text-fg-3" : "text-fg-2")}>{o ? (o.result?.summary ?? o.errorMessage ?? "") : s.state === "RUNNING" ? "Querying…" : s.dependsOn.length ? "Waiting for inputs" : "Queued"}</span>
                </td>
                <td className="mono tabular text-right align-middle text-[11px] text-fg-3">{o && !o.cached && o.status !== "SKIPPED" && o.status !== "NOT_CONFIGURED" ? duration(o.latencyMs) : "—"}</td>
                <td className="hidden text-right align-middle text-xs text-fg-4 md:table-cell">{o ? <Time iso={o.retrievedAt} /> : "—"}</td>
                <td className="align-middle">{o && <ChevronRight size={13} className="text-fg-4" />}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

interface RawResponse {
  provider: string;
  status: string;
  retrievedAt: string;
  diagnostics?: ProviderOutcome["diagnostics"];
  raw: unknown;
}

function RawPanel({ investigationId, provider }: { investigationId: string; provider: string }) {
  const [data, setData] = useState<RawResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    api<RawResponse>(`/api/investigations/${investigationId}/raw?provider=${encodeURIComponent(provider)}`)
      .then((d) => alive && setData(d))
      .catch((e: Error) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [investigationId, provider]);
  if (error) return <ErrorNote title="Raw response unavailable">{error}</ErrorNote>;
  if (!data) return <Skeleton className="h-[160px]" />;
  if (data.raw === null || data.raw === undefined) return <div className="text-sm text-fg-3">This source stored no raw payload (it either did not answer, or the analysis is computed locally).</div>;
  const text = JSON.stringify(data.raw, null, 2);
  return (
    <div className="relative">
      <div className="absolute top-1.5 right-1.5">
        <CopyButton value={text} label="Copy raw JSON" />
      </div>
      <pre className="mono max-h-[52vh] overflow-auto rounded-[2px] bg-ink-0 p-3 text-[11px] leading-[1.55] text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{text}</pre>
      <p className="mt-2 text-2xs text-fg-4">Credential-like fields are redacted before storage; payloads over 300 KB are not stored.</p>
    </div>
  );
}

export function SourceDrawer({ provider, focus, onClose }: { provider: string | null; focus?: "raw"; onClose: () => void }) {
  const { inv } = useWorkspace();
  const { get } = useCatalog();
  const [showRaw, setShowRaw] = useState(false);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- sync with the requested focus
    setShowRaw(focus === "raw");
  }, [provider, focus]);
  const meta = provider ? get(provider) : undefined;
  const o = inv.providerResults.find((r) => r.provider === provider);
  const findings = inv.findings.filter((f) => f.source === provider);

  return (
    <Drawer
      open={Boolean(provider)}
      onClose={onClose}
      width={640}
      title={
        <span className="flex items-center gap-2.5">
          {provider && <Prov id={provider} />}
          {meta?.name ?? provider}
        </span>
      }
      subtitle={meta ? `${meta.vendor} · ${CATEGORY_LABELS[meta.category]}${meta.active ? " · contacts the target directly" : ""}` : undefined}
    >
      {o ? (
        <div className="flex flex-col gap-5 px-5 py-4">
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
            <div>
              <div className="label mb-1">State</div>
              <StatusLabel state={o.status} />
            </div>
            <div>
              <div className="label mb-1">Latency</div>
              <span className="mono tabular text-sm">{o.cached ? "cached" : duration(o.latencyMs)}</span>
            </div>
            <div>
              <div className="label mb-1">Retrieved</div>
              <Time iso={o.retrievedAt} mode="absolute" seconds className="mono text-[11.5px]" />
            </div>
            <div>
              <div className="label mb-1">HTTP</div>
              <span className="mono text-sm">{o.httpStatus ?? "—"}</span>
            </div>
          </div>

          {o.errorMessage && (
            <div className="rounded-[2px] border-l-2 bg-ink-2 px-3 py-2 text-sm text-fg-2" style={{ borderColor: statusColor(o.status) }}>
              <div className="mb-0.5 flex items-center gap-2 text-xs text-fg-3">
                <StatusDot state={o.status} />
                {o.errorType}
              </div>
              {o.errorMessage}
            </div>
          )}

          {o.result && (
            <>
              <div>
                <div className="label mb-1.5">Summary</div>
                <p className="text-sm text-fg-1">{o.result.summary}</p>
              </div>
              {o.result.facts.length > 0 && (
                <div>
                  <div className="label mb-1">Normalised result</div>
                  <FactsGrid facts={o.result.facts} columns={1} />
                </div>
              )}
              {!!o.result.links?.length && (
                <div className="flex flex-wrap gap-2">
                  {o.result.links.map((l) => (
                    <a key={l.url} href={l.url} target="_blank" rel="noopener noreferrer nofollow" className="btn btn-sm">
                      {l.label} <ArrowUpRight size={11} />
                    </a>
                  ))}
                </div>
              )}
            </>
          )}

          {findings.length > 0 && (
            <div>
              <div className="label mb-1.5">Findings from this source</div>
              <ul className="divide-y divide-line-1 rounded-[2px] border border-line-1">
                {findings.map((f) => (
                  <FindingItem key={f.id} finding={f} />
                ))}
              </ul>
            </div>
          )}

          {o.diagnostics && (
            <div>
              <div className="label mb-1.5 flex items-center gap-1.5">
                <Database size={11} /> Request diagnostics
              </div>
              <dl className="mono grid grid-cols-[120px_1fr] gap-y-1 text-[11.5px]">
                {o.diagnostics.endpoint && (
                  <>
                    <dt className="text-fg-4">endpoint</dt>
                    <dd className="break-all text-fg-2">{o.diagnostics.endpoint}</dd>
                  </>
                )}
                <dt className="text-fg-4">requests</dt>
                <dd className="text-fg-2">{o.diagnostics.requests ?? 0}</dd>
                {o.diagnostics.bytes !== undefined && (
                  <>
                    <dt className="text-fg-4">bytes</dt>
                    <dd className="text-fg-2">{o.diagnostics.bytes.toLocaleString("en-GB")}</dd>
                  </>
                )}
                <dt className="text-fg-4">validation</dt>
                <dd className="text-fg-2">{o.diagnostics.validation ?? "not-applicable"}</dd>
                {o.diagnostics.note && (
                  <>
                    <dt className="text-fg-4">note</dt>
                    <dd className="text-fg-2">{o.diagnostics.note}</dd>
                  </>
                )}
              </dl>
            </div>
          )}

          <div>
            <button type="button" className="btn btn-sm" aria-expanded={showRaw} onClick={() => setShowRaw((s) => !s)}>
              <Braces size={12} /> {showRaw ? "Hide raw response" : "Show raw response"}
            </button>
            {showRaw && provider && (
              <div className="mt-3 animate-fade">
                <RawPanel investigationId={inv.id} provider={provider} />
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="px-5 py-8 text-sm text-fg-3">This source has not finished yet.</div>
      )}
    </Drawer>
  );
}
