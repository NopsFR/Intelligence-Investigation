"use client";

import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { COMMAND_CATEGORY_LABEL, COMMANDS, type CommandCategory } from "@/lib/knowledge/commands";
import { CopyButton, EmptyState } from "@/components/ui/primitives";
import { Mono } from "../analysis/common";

const CATEGORIES = Object.keys(COMMAND_CATEGORY_LABEL) as CommandCategory[];

export function CommandReference() {
  const [tab, setTab] = useState<CommandCategory>("linux");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return COMMANDS[tab].filter((c) => !q || c.command.toLowerCase().includes(q) || c.description.toLowerCase().includes(q));
  }, [tab, query]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1">
          <Search size={14} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-fg-4" />
          <input className="input h-9 w-full pl-8" placeholder="Search commands…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search command reference" />
        </div>
        <span className="ml-auto text-xs text-fg-4">
          {filtered.length} of {COMMANDS[tab].length}
        </span>
      </div>

      <div role="tablist" aria-label="Command category" className="scrollbar-none relative flex overflow-x-auto border-b border-line-1">
        {CATEGORIES.map((c) => (
          <button
            key={c}
            type="button"
            role="tab"
            aria-selected={tab === c}
            onClick={() => setTab(c)}
            className={`relative flex h-[38px] shrink-0 items-center px-3 text-sm font-medium transition-colors ${tab === c ? "text-fg-1 after:absolute after:bottom-0 after:left-0 after:h-[2px] after:w-full after:bg-signal" : "text-fg-3 hover:text-fg-1"}`}
          >
            {COMMAND_CATEGORY_LABEL[c]}
          </button>
        ))}
      </div>

      {!filtered.length ? (
        <EmptyState icon={<Search size={17} />} title="No commands match">
          Try a different search term.
        </EmptyState>
      ) : (
        <ul className="panel panel-ticks divide-y divide-line-1">
          {filtered.map((c) => (
            <li key={c.command} className="flex flex-col gap-1.5 px-[var(--panel-pad)] py-3 sm:flex-row sm:items-start sm:gap-4">
              <div className="flex shrink-0 items-center gap-1 sm:w-[380px]">
                <Mono className="min-w-0 flex-1 break-all text-fg-1">{c.command}</Mono>
                <CopyButton value={c.command} label={`Copy ${c.command}`} />
              </div>
              <div className="min-w-0 flex-1 text-sm text-fg-3">
                {c.description}
                {c.example && (
                  <div className="mt-1 flex items-center gap-1">
                    <Mono className="text-xs text-fg-4">{c.example}</Mono>
                    <CopyButton value={c.example} label={`Copy example ${c.example}`} />
                  </div>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
