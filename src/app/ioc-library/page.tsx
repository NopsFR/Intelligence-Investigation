"use client";

import { useEffect, useState } from "react";
import { Plus, Trash2 } from "lucide-react";

interface IocItem {
  id: string;
  value: string;
  type: string;
  notes: string | null;
  tags: string[];
  source: string | null;
  createdAt: string;
  updatedAt: string;
}

export default function IocLibraryPage() {
  const [items, setItems] = useState<IocItem[] | null>(null);
  const [value, setValue] = useState("");
  const [notes, setNotes] = useState("");
  const [tags, setTags] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function load() {
    const res = await fetch("/api/ioc");
    const data = await res.json();
    setItems(data.items);
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- initial data load on mount
    load();
  }, []);

  async function addIoc() {
    if (!value.trim()) return;
    setSubmitting(true);
    setError(null);
    const res = await fetch("/api/ioc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        value: value.trim(),
        notes: notes.trim() || undefined,
        tags: tags.trim() ? tags.split(",").map((t) => t.trim()).filter(Boolean) : undefined,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      setError(data.error ?? "Could not add this IOC.");
    } else {
      setValue("");
      setNotes("");
      setTags("");
      await load();
    }
    setSubmitting(false);
  }

  async function remove(id: string) {
    await fetch(`/api/ioc/${id}`, { method: "DELETE" });
    await load();
  }

  return (
    <div className="mx-auto max-w-[1200px] px-4 md:px-6 py-10 space-y-6">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-1">
          {items?.length ?? 0} entries
        </p>
        <h1 className="text-2xl font-medium text-[var(--nops-text)]">IOC Library</h1>
      </div>

      <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] p-4 space-y-3">
        <div className="flex flex-wrap gap-2">
          <input
            className="flex-1 min-w-[200px] rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-3 py-2 font-mono text-sm text-[var(--nops-text)] outline-none focus:border-[var(--nops-red-dim)]"
            placeholder="IP, domain, URL, hash, or CVE"
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <input
            className="flex-1 min-w-[160px] rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-3 py-2 font-mono text-sm text-[var(--nops-text)] outline-none"
            placeholder="tags (comma separated)"
            value={tags}
            onChange={(e) => setTags(e.target.value)}
          />
        </div>
        <textarea
          className="w-full rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-3 py-2 font-mono text-sm text-[var(--nops-text)] outline-none"
          placeholder="Notes"
          rows={2}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
        <button
          onClick={addIoc}
          disabled={submitting || !value.trim()}
          className="inline-flex items-center gap-1.5 rounded border border-[var(--nops-red-dim)] bg-[var(--nops-red-bg)] px-4 py-2 font-mono text-xs uppercase tracking-wider text-[var(--nops-red)] disabled:opacity-40"
        >
          <Plus size={13} /> Add to library
        </button>
        {error && <p className="font-mono text-xs text-[var(--nops-red)]">{error}</p>}
      </div>

      {!items ? (
        <p className="font-mono text-sm text-[var(--nops-text-faint)]">Loading…</p>
      ) : items.length === 0 ? (
        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] px-4 py-10 text-center font-mono text-sm text-[var(--nops-text-faint)]">
          No IOCs recorded yet.
        </div>
      ) : (
        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)]">
          <ul>
            {items.map((item) => (
              <li key={item.id} className="border-b border-[var(--nops-border)] last:border-b-0 px-4 py-3 flex items-start gap-3">
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-sm text-[var(--nops-text)] break-all">{item.value}</p>
                  <p className="font-mono text-[11px] text-[var(--nops-text-faint)]">
                    {item.type} · {item.source ?? "Manual entry"} · added{" "}
                    {new Date(item.createdAt).toLocaleDateString()}
                  </p>
                  {item.notes && <p className="text-xs text-[var(--nops-text-dim)] mt-1">{item.notes}</p>}
                  {item.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {item.tags.map((t) => (
                        <span key={t} className="rounded border border-[var(--nops-border-strong)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--nops-text-dim)]">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <button onClick={() => remove(item.id)} className="p-1.5 text-[var(--nops-text-faint)] hover:text-[var(--nops-red)]" aria-label="Remove">
                  <Trash2 size={14} />
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
