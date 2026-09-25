"use client";

import { Briefcase, Plus } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api, ApiClientError } from "@/lib/client/api";
import { useSession } from "@/lib/client/session";
import { EmptyState, ErrorNote } from "@/components/ui/primitives";
import { Dialog, useToast } from "@/components/ui/overlays";
import { Chip } from "../analysis/common";
import { Time } from "../ui/Time";

interface CaseSummary {
  id: string;
  title: string;
  description: string | null;
  status: "OPEN" | "CLOSED" | "ARCHIVED";
  severity: string | null;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  itemCounts: Record<string, number>;
}

const STATUS_TONE = { OPEN: "ice", CLOSED: "ok", ARCHIVED: "neutral" } as const;

export function CasesList() {
  const operator = useSession().session?.operator ?? false;
  const [cases, setCases] = useState<CaseSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const toast = useToast();

  const load = () => {
    api<{ items: CaseSummary[] }>("/api/cases")
      .then((r) => setCases(r.items))
      .catch((e: ApiClientError) => setError(e.message));
  };
  useEffect(() => {
    setTimeout(load, 0);
  }, []);

  if (error) return <ErrorNote title="Could not load cases">{error}</ErrorNote>;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        <button type="button" className="btn btn-primary" disabled={!operator} title={operator ? undefined : "Unlock an operator session to create a case"} onClick={() => setOpen(true)}>
          <Plus size={14} /> New case
        </button>
      </div>

      {!cases ? (
        <div className="panel flex flex-col gap-2 p-4" aria-busy="true">
          <div className="skeleton h-4 w-1/3" />
          <div className="skeleton h-4 w-1/2" />
        </div>
      ) : !cases.length ? (
        <EmptyState icon={<Briefcase size={17} />} title="No cases yet">
          Cases hold the notes, evidence, chain-of-custody log and timeline for an incident, alongside the investigations and indicators it involves.
        </EmptyState>
      ) : (
        <ul className="panel divide-y divide-line-1">
          {cases.map((c) => (
            <li key={c.id}>
              <Link href={`/cases/${c.id}`} className="flex flex-wrap items-center gap-3 px-[var(--panel-pad)] py-3 hover:bg-ink-2">
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium text-fg-1">{c.title}</span>
                  {c.description && <span className="mt-0.5 block truncate text-xs text-fg-3">{c.description}</span>}
                </span>
                <Chip tone={STATUS_TONE[c.status]}>{c.status}</Chip>
                {c.severity && <Chip tone={c.severity === "CRITICAL" || c.severity === "HIGH" ? "err" : c.severity === "MEDIUM" ? "warn" : "neutral"}>{c.severity}</Chip>}
                <span className="text-xs text-fg-4">
                  {Object.values(c.itemCounts).reduce((a, b) => a + b, 0)} item{Object.values(c.itemCounts).reduce((a, b) => a + b, 0) === 1 ? "" : "s"}
                </span>
                <Time iso={c.updatedAt} className="w-[110px] text-right text-xs text-fg-4" />
              </Link>
            </li>
          ))}
        </ul>
      )}

      <NewCaseDialog
        open={open}
        onClose={() => setOpen(false)}
        onCreated={(c) => {
          toast({ kind: "success", title: "Case created", body: c.title });
          load();
        }}
      />
    </div>
  );
}

function NewCaseDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (c: CaseSummary) => void }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const submit = async () => {
    if (!title.trim()) return;
    setBusy(true);
    try {
      const created = await api<CaseSummary>("/api/cases", { method: "POST", json: { title: title.trim(), description: description.trim() || undefined } });
      setTitle("");
      setDescription("");
      onClose();
      onCreated(created);
    } catch (err) {
      toast({ kind: "error", title: "Could not create the case", body: err instanceof ApiClientError ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="New case"
      footer={
        <>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={!title.trim() || busy} onClick={() => void submit()}>
            Create
          </button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-xs text-fg-3">
          Title
          <input className="input h-9" value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
        </label>
        <label className="flex flex-col gap-1 text-xs text-fg-3">
          Description (optional)
          <textarea className="input h-20 resize-y p-2" value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
      </div>
    </Dialog>
  );
}
