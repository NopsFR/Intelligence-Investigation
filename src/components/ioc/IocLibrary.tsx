"use client";

import { Download, FileInput, Library, Loader2, Radar, Search, Tag, Trash2, X } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { OBSERVABLE_LABELS, OBSERVABLE_TYPES, type ObservableType } from "@/lib/core/types";
import type { IocRecord } from "@/lib/db/ioc";
import { api, type ApiClientError } from "@/lib/client/api";
import { cx } from "@/lib/client/cx";
import { useInvestigate } from "@/lib/client/investigate";
import { InvestigationStatusBadge, TypeTag } from "@/components/ui/badges";
import { Drawer, useToast } from "@/components/ui/overlays";
import { CopyButton, EmptyState } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";

interface Extracted {
  value: string;
  type: ObservableType;
  occurrences: number;
}

function ExtractDrawer({ open, onClose, onAdded }: { open: boolean; onClose: () => void; onAdded: () => void }) {
  const [text, setText] = useState("");
  const [found, setFound] = useState<Extracted[] | null>(null);
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [tags, setTags] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const extract = async () => {
    setBusy(true);
    try {
      const res = await api<{ indicators: Extracted[] }>("/api/extract", { method: "POST", json: { text } });
      setFound(res.indicators);
      setExcluded(new Set());
    } catch (e) {
      toast({ kind: "error", title: "Extraction failed", body: (e as ApiClientError).message });
    } finally {
      setBusy(false);
    }
  };

  const add = async () => {
    const entries = (found ?? []).filter((f) => !excluded.has(`${f.type}:${f.value}`)).map((f) => ({ value: f.value, type: f.type, tags: tags.split(/[,\s]+/).filter(Boolean) }));
    if (!entries.length) return;
    setBusy(true);
    try {
      const r = await api<{ created: number; updated: number; rejected: string[] }>("/api/ioc", { method: "POST", json: { entries, source: "extraction" } });
      toast({ kind: "success", title: `${r.created} added, ${r.updated} updated`, body: r.rejected.length ? `${r.rejected.length} rejected` : undefined });
      setText("");
      setFound(null);
      onAdded();
      onClose();
    } catch (e) {
      toast({ kind: "error", title: "Could not add indicators", body: (e as ApiClientError).message });
    } finally {
      setBusy(false);
    }
  };

  const grouped = useMemo(() => {
    const m = new Map<ObservableType, Extracted[]>();
    for (const f of found ?? []) m.set(f.type, [...(m.get(f.type) ?? []), f]);
    return [...m.entries()];
  }, [found]);
  const selectedCount = (found?.length ?? 0) - excluded.size;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Extract indicators"
      subtitle="Paste a report, email, log excerpt or alert. Defanged indicators (hxxp, [.], [at]) are refanged; every candidate is validated before it is offered."
      width={620}
      footer={
        found && (
          <div className="flex items-center gap-2">
            <label className="relative flex-1">
              <span className="sr-only">Tags</span>
              <Tag size={12} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-fg-4" />
              <input className="input h-[30px] pl-7 text-xs" placeholder="Tags (comma separated), e.g. phishing, case-1142" value={tags} onChange={(e) => setTags(e.target.value)} />
            </label>
            <button type="button" className="btn btn-primary btn-sm" onClick={() => void add()} disabled={busy || selectedCount === 0}>
              {busy ? <Loader2 size={12} className="animate-spin" /> : <Library size={12} />} Add {selectedCount}
            </button>
          </div>
        )
      }
    >
      <div className="flex flex-col gap-4 p-5">
        <textarea className="input mono min-h-[180px] text-[12px]" placeholder={"e.g.\nC2 at hxxp://203[.]0.113[.]7/gate.php\nPayload sha256 44d88612fea8a8f36de82e1278abb02f…"} value={text} onChange={(e) => setText(e.target.value)} data-autofocus />
        <button type="button" className="btn self-start" onClick={() => void extract()} disabled={busy || !text.trim()}>
          {busy && !found ? <Loader2 size={13} className="animate-spin" /> : <FileInput size={13} />} Extract
        </button>
        {found &&
          (found.length ? (
            <div className="flex flex-col gap-3">
              {grouped.map(([type, items]) => (
                <div key={type}>
                  <div className="label mb-1.5">
                    {OBSERVABLE_LABELS[type]} · {items.length}
                  </div>
                  <ul className="divide-y divide-line-1 rounded-[2px] border border-line-1">
                    {items.map((f) => {
                      const key = `${f.type}:${f.value}`;
                      const on = !excluded.has(key);
                      return (
                        <li key={key}>
                          <label className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-ink-2">
                            <input type="checkbox" checked={on} onChange={() => setExcluded((s) => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n; })} className="accent-[var(--color-fg-2)]" />
                            <span className={cx("mono min-w-0 flex-1 truncate text-[12px]", on ? "text-fg-1" : "text-fg-4 line-through")}>{f.value}</span>
                            {f.occurrences > 1 && <span className="mono text-[10.5px] text-fg-4">×{f.occurrences}</span>}
                          </label>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-fg-3">No valid indicators found in that text.</p>
          ))}
      </div>
    </Drawer>
  );
}

export function IocLibrary({ initial }: { initial: IocRecord[] }) {
  const [items, setItems] = useState(initial);
  const [q, setQ] = useState("");
  const [type, setType] = useState<ObservableType | "">("");
  const [tag, setTag] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [extract, setExtract] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [draftTags, setDraftTags] = useState("");
  const toast = useToast();
  const { start } = useInvestigate();

  const reload = async () => {
    const sp = new URLSearchParams();
    if (q) sp.set("q", q);
    if (type) sp.set("type", type);
    if (tag) sp.set("tag", tag);
    try {
      setItems((await api<{ items: IocRecord[] }>(`/api/ioc?${sp}`)).items);
    } catch (e) {
      toast({ kind: "error", title: "Could not load the library", body: (e as ApiClientError).message });
    }
  };

  useEffect(() => {
    const t = setTimeout(() => void reload(), 200);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reload on filter change only
  }, [q, type, tag]);

  const tags = useMemo(() => [...new Set(items.flatMap((i) => i.tags))].sort(), [items]);

  const remove = async (ids: string[]) => {
    try {
      const r = await api<{ deleted: number }>("/api/ioc", { method: "DELETE", json: { ids } });
      toast({ kind: "success", title: `${r.deleted} indicator${r.deleted === 1 ? "" : "s"} removed` });
      setSelected(new Set());
      await reload();
    } catch (e) {
      toast({ kind: "error", title: "Could not remove", body: (e as ApiClientError).message });
    }
  };

  const saveTags = async (id: string) => {
    try {
      await api(`/api/ioc/${id}`, { method: "PATCH", json: { tags: draftTags.split(/[,\s]+/).filter(Boolean) } });
      setEditing(null);
      await reload();
    } catch (e) {
      toast({ kind: "error", title: "Could not save tags", body: (e as ApiClientError).message });
    }
  };

  const exportQuery = new URLSearchParams({ ...(q ? { q } : {}), ...(type ? { type } : {}), ...(tag ? { tag } : {}) }).toString();

  return (
    <div className="panel panel-ticks">
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <label className="relative min-w-[200px] flex-1 sm:max-w-[300px]">
          <span className="sr-only">Search indicators</span>
          <Search size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-fg-4" />
          <input className="input mono h-[30px] pl-8 text-[12px]" placeholder="Search value or notes" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <select className="input h-[30px] w-auto text-xs" value={type} onChange={(e) => setType(e.target.value as ObservableType | "")} aria-label="Type">
          <option value="">All types</option>
          {OBSERVABLE_TYPES.map((t) => (
            <option key={t} value={t}>
              {OBSERVABLE_LABELS[t]}
            </option>
          ))}
        </select>
        {tags.length > 0 && (
          <select className="input h-[30px] w-auto text-xs" value={tag} onChange={(e) => setTag(e.target.value)} aria-label="Tag">
            <option value="">Any tag</option>
            {tags.map((t) => (
              <option key={t} value={t}>
                #{t}
              </option>
            ))}
          </select>
        )}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {selected.size > 0 && (
            <button type="button" className="btn btn-sm" onClick={() => void remove([...selected])}>
              <Trash2 size={12} /> Remove {selected.size}
            </button>
          )}
          <a className="btn btn-ghost btn-sm" href={`/api/ioc/export?format=csv&${exportQuery}`}>
            <Download size={12} /> CSV
          </a>
          <a className="btn btn-ghost btn-sm" href={`/api/ioc/export?format=stix&${exportQuery}`} title="STIX 2.1 bundle of indicator objects">
            <Download size={12} /> STIX 2.1
          </a>
          <a className="btn btn-ghost btn-sm" href={`/api/ioc/export?format=json&${exportQuery}`}>
            <Download size={12} /> JSON
          </a>
          <button type="button" className="btn btn-primary btn-sm" onClick={() => setExtract(true)}>
            <FileInput size={12} /> Extract from text
          </button>
        </div>
      </div>

      {items.length ? (
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th className="w-[36px]">
                  <input type="checkbox" aria-label="Select all" checked={selected.size === items.length} onChange={() => setSelected(selected.size === items.length ? new Set() : new Set(items.map((i) => i.id)))} className="accent-[var(--color-fg-2)]" />
                </th>
                <th>Indicator</th>
                <th>Tags</th>
                <th>Last investigation</th>
                <th className="text-right">Updated</th>
                <th className="w-[110px]" />
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id} data-selected={selected.has(i.id) || undefined} className="group">
                  <td className="align-middle">
                    <input type="checkbox" aria-label={`Select ${i.value}`} checked={selected.has(i.id)} onChange={() => setSelected((s) => { const n = new Set(s); if (n.has(i.id)) n.delete(i.id); else n.add(i.id); return n; })} className="accent-[var(--color-fg-2)]" />
                  </td>
                  <td className="max-w-[440px]">
                    <div className="flex items-center gap-2">
                      <TypeTag type={i.type} />
                      <span className="mono truncate text-[12.5px] text-fg-1">{i.value}</span>
                      <span className="opacity-0 transition-opacity group-hover:opacity-100">
                        <CopyButton value={i.value} />
                      </span>
                    </div>
                    {i.notes && <div className="mt-1 line-clamp-1 pl-[46px] text-xs text-fg-3">{i.notes}</div>}
                  </td>
                  <td className="align-middle">
                    {editing === i.id ? (
                      <form className="flex gap-1" onSubmit={(e) => (e.preventDefault(), void saveTags(i.id))}>
                        <input className="input h-[26px] w-[180px] text-xs" value={draftTags} onChange={(e) => setDraftTags(e.target.value)} autoFocus aria-label="Tags" />
                        <button type="button" className="btn btn-ghost btn-sm btn-icon" onClick={() => setEditing(null)} aria-label="Cancel">
                          <X size={12} />
                        </button>
                      </form>
                    ) : (
                      <button type="button" className="flex flex-wrap gap-1 text-left" onClick={() => (setEditing(i.id), setDraftTags(i.tags.join(", ")))} aria-label={`Edit tags for ${i.value}`}>
                        {i.tags.length ? i.tags.map((t) => <span key={t} className="mono rounded-[2px] bg-ink-2 px-1.5 text-[10.5px] text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">#{t}</span>) : <span className="text-xs text-fg-4 group-hover:text-fg-3">Add tags</span>}
                      </button>
                    )}
                  </td>
                  <td className="align-middle text-xs">
                    {i.lastInvestigation ? (
                      <Link href={`/investigations/${i.lastInvestigation.id}`} className="flex items-center gap-2 hover:underline">
                        <InvestigationStatusBadge status={i.lastInvestigation.status as "COMPLETE"} />
                        <Time iso={i.lastInvestigation.createdAt} className="text-fg-3" />
                      </Link>
                    ) : (
                      <span className="text-fg-4">Never</span>
                    )}
                  </td>
                  <td className="text-right align-middle text-xs text-fg-4">
                    <Time iso={i.updatedAt} />
                  </td>
                  <td className="text-right align-middle">
                    <button type="button" className="btn btn-sm" onClick={() => void start(i.value, "QUICK", { type: i.type })}>
                      <Radar size={12} /> Scan
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          icon={<Library size={16} />}
          title={q || type || tag ? "No indicators match" : "The library is empty"}
          action={
            <button type="button" className="btn btn-sm" onClick={() => setExtract(true)}>
              <FileInput size={12} /> Extract from text
            </button>
          }
        >
          Track indicators across investigations. Add them from an investigation’s menu, or paste a report and extract them.
        </EmptyState>
      )}
      <ExtractDrawer open={extract} onClose={() => setExtract(false)} onAdded={() => void reload()} />
    </div>
  );
}
