"use client";

import { ArrowLeft, ClipboardList, FileText, Link2, Plus, ShieldCheck, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api, ApiClientError } from "@/lib/client/api";
import { useSession } from "@/lib/client/session";
import { Dialog, useToast } from "@/components/ui/overlays";
import { Chip, Mono } from "../analysis/common";
import { Time } from "../ui/Time";

type Kind = "NOTE" | "EVIDENCE" | "CUSTODY" | "EVENT" | "LINK";

interface CaseItem {
  id: string;
  kind: Kind;
  createdAt: string;
  author: string;
  data: Record<string, unknown>;
}
interface CaseRecord {
  id: string;
  title: string;
  description: string | null;
  status: "OPEN" | "CLOSED" | "ARCHIVED";
  severity: string | null;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  items: CaseItem[];
}

const KIND_META: Record<Kind, { label: string; icon: typeof FileText }> = {
  NOTE: { label: "Note", icon: FileText },
  EVIDENCE: { label: "Evidence", icon: ShieldCheck },
  CUSTODY: { label: "Custody", icon: ClipboardList },
  EVENT: { label: "Timeline event", icon: ClipboardList },
  LINK: { label: "Link", icon: Link2 },
};

export type CaseRecordInput = CaseRecord;

export function CaseWorkspace({ initial }: { initial: CaseRecord }) {
  const router = useRouter();
  const operator = useSession().session?.operator ?? false;
  const [record, setRecord] = useState(initial);
  const [addKind, setAddKind] = useState<Kind | null>(null);
  const [filter, setFilter] = useState<Kind | "ALL">("ALL");
  const toast = useToast();

  const refresh = async () => {
    try {
      const r = await api<CaseRecord>(`/api/cases/${record.id}`);
      setRecord(r);
    } catch {
      // keep last known state
    }
  };

  const setStatus = async (status: CaseRecord["status"]) => {
    try {
      const r = await api<CaseRecord>(`/api/cases/${record.id}`, { method: "PATCH", json: { status } });
      setRecord(r);
    } catch (err) {
      toast({ kind: "error", title: "Could not update status", body: err instanceof ApiClientError ? err.message : String(err) });
    }
  };

  const removeCase = async () => {
    if (!confirm(`Delete case "${record.title}"? This removes every note, evidence entry and custody record. This cannot be undone.`)) return;
    try {
      await api(`/api/cases/${record.id}`, { method: "DELETE" });
      toast({ kind: "success", title: "Case deleted", body: record.title });
      router.push("/cases");
    } catch (err) {
      toast({ kind: "error", title: "Could not delete the case", body: err instanceof ApiClientError ? err.message : String(err) });
    }
  };

  const removeItem = async (itemId: string) => {
    try {
      await api(`/api/cases/${record.id}/items/${itemId}`, { method: "DELETE" });
      setRecord((r) => ({ ...r, items: r.items.filter((i) => i.id !== itemId) }));
    } catch (err) {
      toast({ kind: "error", title: "Could not remove the item", body: err instanceof ApiClientError ? err.message : String(err) });
    }
  };

  const items = filter === "ALL" ? record.items : record.items.filter((i) => i.kind === filter);
  const counts = record.items.reduce<Record<string, number>>((m, i) => ((m[i.kind] = (m[i.kind] ?? 0) + 1), m), {});

  return (
    <div className="flex flex-col gap-4">
      <div className="panel panel-ticks">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-3 border-b border-line-1 p-[var(--panel-pad)]">
          <div className="min-w-0 flex-1">
            <Link href="/cases" className="mb-1.5 inline-flex items-center gap-1 text-xs text-fg-4 hover:text-fg-1">
              <ArrowLeft size={11} /> Cases
            </Link>
            <h2 className="display text-xl text-fg-1">{record.title}</h2>
            {record.description && <p className="mt-1 max-w-2xl text-sm text-fg-3">{record.description}</p>}
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <Chip tone={record.status === "OPEN" ? "ice" : record.status === "CLOSED" ? "ok" : "neutral"}>{record.status}</Chip>
              {record.severity && <Chip tone={record.severity === "CRITICAL" || record.severity === "HIGH" ? "err" : "warn"}>{record.severity}</Chip>}
              {record.tags.map((t) => (
                <Chip key={t}>{t}</Chip>
              ))}
              <span className="text-xs text-fg-4">
                opened <Time iso={record.createdAt} /> · updated <Time iso={record.updatedAt} />
              </span>
            </div>
          </div>
          {operator && (
            <div className="flex flex-wrap items-center gap-1.5">
              {record.status !== "CLOSED" && (
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => void setStatus("CLOSED")}>
                  Close case
                </button>
              )}
              {record.status !== "OPEN" && (
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => void setStatus("OPEN")}>
                  Reopen
                </button>
              )}
              {record.status !== "ARCHIVED" && (
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => void setStatus("ARCHIVED")}>
                  Archive
                </button>
              )}
              <button type="button" className="btn btn-ghost btn-sm text-err" onClick={() => void removeCase()}>
                <Trash2 size={13} /> Delete
              </button>
            </div>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 px-[var(--panel-pad)] py-2.5">
          <button type="button" className={`btn btn-sm ${filter === "ALL" ? "btn-primary" : "btn-ghost"}`} onClick={() => setFilter("ALL")}>
            All <span className="mono text-[10.5px] opacity-70">{record.items.length}</span>
          </button>
          {(Object.keys(KIND_META) as Kind[]).map((k) => (
            <button key={k} type="button" className={`btn btn-sm ${filter === k ? "btn-primary" : "btn-ghost"}`} onClick={() => setFilter(k)} disabled={!counts[k]}>
              {KIND_META[k].label} <span className="mono text-[10.5px] opacity-70">{counts[k] ?? 0}</span>
            </button>
          ))}
          {operator && (
            <div className="ml-auto flex flex-wrap gap-1.5">
              {(Object.keys(KIND_META) as Kind[])
                .filter((k) => k !== "LINK")
                .map((k) => (
                  <button key={k} type="button" className="btn btn-ghost btn-sm" onClick={() => setAddKind(k)}>
                    <Plus size={12} /> {KIND_META[k].label}
                  </button>
                ))}
            </div>
          )}
        </div>
      </div>

      {!items.length ? (
        <div className="panel p-6 text-center text-sm text-fg-3">Nothing here yet.</div>
      ) : (
        <ol className="flex flex-col gap-3">
          {[...items].reverse().map((item) => (
            <ItemCard key={item.id} item={item} caseId={record.id} onDelete={operator ? () => void removeItem(item.id) : undefined} />
          ))}
        </ol>
      )}

      {addKind && operator && (
        <AddItemDialog
          kind={addKind}
          onClose={() => setAddKind(null)}
          onAdd={async (data) => {
            try {
              await api(`/api/cases/${record.id}/items`, { method: "POST", json: { kind: addKind, data } });
              setAddKind(null);
              await refresh();
            } catch (err) {
              toast({ kind: "error", title: "Could not add the item", body: err instanceof ApiClientError ? err.message : String(err) });
            }
          }}
        />
      )}
    </div>
  );
}

function ItemCard({ item, onDelete }: { item: CaseItem; caseId: string; onDelete?: () => void }) {
  const meta = KIND_META[item.kind];
  const Icon = meta.icon;
  return (
    <li className="panel p-[var(--panel-pad)]">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-[3px] border border-line-2 bg-ink-2 text-fg-3" aria-hidden>
          <Icon size={13} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="label">{meta.label}</span>
            <span className="text-xs text-fg-4">
              {item.author} · <Time iso={item.createdAt} mode="absolute" seconds />
            </span>
            {onDelete && (
              <button type="button" className="btn btn-ghost btn-sm btn-icon ml-auto" aria-label="Remove item" onClick={onDelete}>
                <Trash2 size={12} />
              </button>
            )}
          </div>
          <ItemBody kind={item.kind} data={item.data} />
        </div>
      </div>
    </li>
  );
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function ItemBody({ kind, data }: { kind: Kind; data: Record<string, unknown> }) {
  if (kind === "NOTE") return <p className="mt-1.5 text-sm whitespace-pre-wrap text-fg-1">{String(data.text ?? "")}</p>;
  if (kind === "EVIDENCE")
    return (
      <div className="mt-1.5">
        <p className="text-sm font-medium text-fg-1">{String(data.label ?? "")}</p>
        {str(data.description) && <p className="mt-0.5 text-xs text-fg-3">{str(data.description)}</p>}
        <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
          {(["sha256", "sha1", "md5"] as const).map((k) => str(data[k]) && (
            <span key={k} className="text-xs">
              <span className="text-fg-4">{k.toUpperCase()}</span> <Mono className="text-fg-2">{str(data[k])}</Mono>
            </span>
          ))}
          {str(data.source) && <span className="text-xs text-fg-4">source: {str(data.source)}</span>}
        </div>
      </div>
    );
  if (kind === "CUSTODY")
    return (
      <div className="mt-1.5 text-sm">
        <span className="font-medium text-fg-1">{String(data.action ?? "")}</span> <span className="text-fg-3">by {String(data.handler ?? "")}</span>
        {str(data.detail) && <p className="mt-0.5 text-xs text-fg-3">{str(data.detail)}</p>}
      </div>
    );
  if (kind === "EVENT")
    return (
      <div className="mt-1.5">
        <div className="flex items-center gap-2 text-sm">
          <Mono className="text-fg-3">{String(data.occurredAt ?? "")}</Mono>
          <span className="font-medium text-fg-1">{String(data.title ?? "")}</span>
        </div>
        {str(data.detail) && <p className="mt-0.5 text-xs text-fg-3">{str(data.detail)}</p>}
        {str(data.source) && <p className="mt-0.5 text-xs text-fg-4">source: {str(data.source)}</p>}
      </div>
    );
  return (
    <div className="mt-1.5 text-sm">
      <Link href={data.refType === "investigation" ? `/investigations/${data.refId}` : "/ioc"} className="link">
        {String(data.label ?? data.refId ?? "")}
      </Link>
      <span className="ml-2 text-xs text-fg-4">{String(data.refType ?? "")}</span>
    </div>
  );
}

function AddItemDialog({ kind, onClose, onAdd }: { kind: Kind; onClose: () => void; onAdd: (data: Record<string, unknown>) => void | Promise<void> }) {
  const [fields, setFields] = useState<Record<string, string>>({});
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setFields((f) => ({ ...f, [k]: e.target.value }));

  const build = (): Record<string, unknown> | null => {
    if (kind === "NOTE") return fields.text?.trim() ? { text: fields.text.trim() } : null;
    if (kind === "EVIDENCE") return fields.label?.trim() ? { label: fields.label.trim(), sha256: fields.sha256?.trim() || undefined, sha1: fields.sha1?.trim() || undefined, md5: fields.md5?.trim() || undefined, description: fields.description?.trim() || undefined, source: fields.source?.trim() || undefined } : null;
    if (kind === "CUSTODY") return fields.action?.trim() && fields.handler?.trim() ? { action: fields.action.trim(), handler: fields.handler.trim(), detail: fields.detail?.trim() || undefined } : null;
    if (kind === "EVENT") return fields.occurredAt?.trim() && fields.title?.trim() ? { occurredAt: fields.occurredAt.trim(), title: fields.title.trim(), detail: fields.detail?.trim() || undefined, source: fields.source?.trim() || undefined } : null;
    return null;
  };
  const valid = build() !== null;

  const FIELD_LABELS: Record<Kind, [string, string, boolean][]> = {
    NOTE: [["text", "Note", true]],
    EVIDENCE: [
      ["label", "Label", false],
      ["sha256", "SHA-256 (optional)", false],
      ["sha1", "SHA-1 (optional)", false],
      ["md5", "MD5 (optional)", false],
      ["description", "Description (optional)", true],
      ["source", "Source (optional)", false],
    ],
    CUSTODY: [
      ["action", "Action (e.g. Collected, Transferred, Analysed)", false],
      ["handler", "Handler", false],
      ["detail", "Detail (optional)", true],
    ],
    EVENT: [
      ["occurredAt", "Occurred at (ISO 8601 or free text)", false],
      ["title", "Title", false],
      ["detail", "Detail (optional)", true],
      ["source", "Source (optional)", false],
    ],
    LINK: [],
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Add ${KIND_META[kind].label.toLowerCase()}`}
      footer={
        <>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={!valid} onClick={() => valid && void onAdd(build()!)}>
            Add
          </button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {FIELD_LABELS[kind].map(([key, label, multiline]) => (
          <label key={key} className="flex flex-col gap-1 text-xs text-fg-3">
            {label}
            {multiline ? <textarea className="input h-20 resize-y p-2" value={fields[key] ?? ""} onChange={set(key)} /> : <input className="input h-9" value={fields[key] ?? ""} onChange={set(key)} autoFocus={key === FIELD_LABELS[kind][0][0]} />}
          </label>
        ))}
      </div>
    </Dialog>
  );
}
