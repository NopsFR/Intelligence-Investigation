"use client";

import { useMemo, useState } from "react";
import { ExternalLink } from "lucide-react";
import { ATTACK_TACTICS, ATTACK_TECHNIQUES, type AttackTechnique } from "@/lib/attack/data";

export default function AttackExplorerPage() {
  const [tactic, setTactic] = useState<string | "all">("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<AttackTechnique | null>(null);

  const filtered = useMemo(() => {
    return ATTACK_TECHNIQUES.filter((t) => {
      if (tactic !== "all" && !t.tacticIds.includes(tactic)) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          t.id.toLowerCase().includes(q) ||
          t.name.toLowerCase().includes(q) ||
          t.subTechniques?.some((s) => s.id.toLowerCase().includes(q) || s.name.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [tactic, search]);

  return (
    <div className="mx-auto max-w-[1400px] px-4 md:px-6 py-10 space-y-6">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-1">
          MITRE ATT&CK Enterprise (curated subset)
        </p>
        <h1 className="text-2xl font-medium text-[var(--nops-text)]">ATT&CK Explorer</h1>
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search technique ID or name..."
          className="flex-1 min-w-[220px] rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)] px-3 py-2 font-mono text-sm text-[var(--nops-text)] outline-none focus:border-[var(--nops-red-dim)]"
        />
        <select
          value={tactic}
          onChange={(e) => setTactic(e.target.value)}
          className="rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)] px-3 py-2 font-mono text-sm text-[var(--nops-text)]"
        >
          <option value="all">All tactics</option>
          {ATTACK_TACTICS.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
      </div>

      <div className="grid lg:grid-cols-[1fr_360px] gap-6">
        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)]">
          <ul>
            {filtered.map((t) => (
              <li key={t.id} className="border-b border-[var(--nops-border)] last:border-b-0">
                <button onClick={() => setSelected(t)} className="w-full text-left px-4 py-3 hover:bg-[var(--nops-bg-raised)] transition-colors">
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-xs text-[var(--nops-red)]">{t.id}</span>
                    <span className="text-sm text-[var(--nops-text)]">{t.name}</span>
                  </div>
                  <p className="font-mono text-[11px] text-[var(--nops-text-faint)] mt-1">
                    {t.tacticIds.map((id) => ATTACK_TACTICS.find((tac) => tac.id === id)?.name).join(", ")}
                  </p>
                  {t.subTechniques && t.subTechniques.length > 0 && (
                    <p className="font-mono text-[11px] text-[var(--nops-text-faint)] mt-1">
                      {t.subTechniques.length} sub-technique(s)
                    </p>
                  )}
                </button>
              </li>
            ))}
            {filtered.length === 0 && (
              <li className="px-4 py-10 text-center font-mono text-sm text-[var(--nops-text-faint)]">No techniques match this filter.</li>
            )}
          </ul>
        </div>

        <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] p-4 h-fit sticky top-20">
          {!selected ? (
            <p className="font-mono text-sm text-[var(--nops-text-faint)]">Select a technique to view its details.</p>
          ) : (
            <div className="space-y-3">
              <div>
                <p className="font-mono text-xs text-[var(--nops-red)]">{selected.id}</p>
                <h2 className="text-lg text-[var(--nops-text)]">{selected.name}</h2>
              </div>
              <p className="text-sm text-[var(--nops-text-dim)]">{selected.description}</p>
              <div>
                <p className="font-mono text-[11px] uppercase tracking-wider text-[var(--nops-text-faint)] mb-1">Tactics</p>
                <div className="flex flex-wrap gap-1">
                  {selected.tacticIds.map((id) => (
                    <span key={id} className="rounded border border-[var(--nops-border-strong)] px-2 py-0.5 font-mono text-[11px] text-[var(--nops-text-dim)]">
                      {ATTACK_TACTICS.find((t) => t.id === id)?.name}
                    </span>
                  ))}
                </div>
              </div>
              {selected.subTechniques && selected.subTechniques.length > 0 && (
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-wider text-[var(--nops-text-faint)] mb-1">Sub-techniques</p>
                  <ul className="space-y-2">
                    {selected.subTechniques.map((s) => (
                      <li key={s.id} className="text-sm">
                        <span className="font-mono text-xs text-[var(--nops-text-dim)]">{s.id}</span>{" "}
                        <span className="text-[var(--nops-text)]">{s.name}</span>
                        <p className="text-xs text-[var(--nops-text-faint)]">{s.description}</p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <a
                href={selected.url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 font-mono text-xs text-[var(--nops-text-dim)] hover:text-[var(--nops-text)]"
              >
                <ExternalLink size={12} /> View on attack.mitre.org
              </a>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
