"use client";

import { GitBranch, Hash, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { EVENT_ID_CHANNELS, EVENT_ID_REFERENCE, type EventIdEntry } from "@/lib/dfir/eventids";
import { compareHashSets, hashKind, parseHashList, type HashSet } from "@/lib/dfir/hashcompare";
import { parseProcessListing, type ProcessNode } from "@/lib/dfir/processtree";
import { buildTimeline } from "@/lib/dfir/timeline";
import { cx } from "@/lib/client/cx";
import { Tabs } from "@/components/ui/overlays";
import { EmptyState, Panel } from "@/components/ui/primitives";
import { Tree, type TreeNode } from "@/components/ui/workbench";
import { AttackChip, Chip, DataTable, Mono } from "../analysis/common";

export function DfirWorkbench() {
  const [tab, setTab] = useState("timeline");
  return (
    <div className="flex flex-col gap-4">
      <Tabs
        label="DFIR tools"
        value={tab}
        onChange={setTab}
        items={[
          { id: "timeline", label: "Timeline" },
          { id: "hashes", label: "Hash compare" },
          { id: "process", label: "Process tree" },
          { id: "events", label: "Event ID reference" },
        ]}
      />
      {tab === "timeline" && <TimelineTool />}
      {tab === "hashes" && <HashCompareTool />}
      {tab === "process" && <ProcessTreeTool />}
      {tab === "events" && <EventIdTool />}
    </div>
  );
}

// ───────────────────────────── Timeline

function TimelineTool() {
  const [sources, setSources] = useState([
    { label: "Source A", text: "" },
    { label: "Source B", text: "" },
  ]);
  const [q, setQ] = useState("");
  const result = useMemo(() => buildTimeline(sources), [sources]);
  const filtered = q ? result.events.filter((e) => e.raw.toLowerCase().includes(q.toLowerCase())) : result.events;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <Panel title="Log sources" meta="Paste lines from one or more logs. Each recognised leading timestamp anchors that line; unrecognised lines are skipped and counted.">
        <div className="flex flex-col gap-3">
          {sources.map((s, i) => (
            <div key={i}>
              <input className="input mb-1.5 h-8 w-full max-w-xs text-sm" value={s.label} onChange={(e) => setSources((list) => list.map((x, k) => (k === i ? { ...x, label: e.target.value } : x)))} aria-label={`Source ${i + 1} label`} />
              <textarea className="input mono h-36 w-full resize-y p-2 text-[11.5px]" placeholder="Paste log lines…" value={s.text} onChange={(e) => setSources((list) => list.map((x, k) => (k === i ? { ...x, text: e.target.value } : x)))} aria-label={`Source ${i + 1} content`} />
            </div>
          ))}
          <button type="button" className="btn btn-ghost btn-sm self-start" onClick={() => setSources((list) => [...list, { label: `Source ${String.fromCharCode(65 + list.length)}`, text: "" }])}>
            + Add source
          </button>
        </div>
      </Panel>
      <Panel
        title="Merged timeline"
        meta={`${result.events.length} events${result.skipped ? ` · ${result.skipped} lines skipped (no recognisable timestamp)` : ""}`}
        actions={
          <div className="relative">
            <Search size={12} className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-fg-4" />
            <input className="input h-7 w-40 pl-7 text-xs" placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter timeline" />
          </div>
        }
        bodyClassName="p-0"
      >
        {!filtered.length ? (
          <EmptyState title="No events yet">Paste log text with timestamps on the left.</EmptyState>
        ) : (
          <ol className="max-h-[560px] divide-y divide-line-1 overflow-auto">
            {filtered.map((e, i) => (
              <li key={i} className="flex flex-wrap items-start gap-x-3 gap-y-0.5 px-3 py-2 text-xs">
                <Mono className="w-[172px] shrink-0 text-fg-3">{e.iso.replace("T", " ").replace(/\.\d+Z$/, "Z")}</Mono>
                <Chip>{e.source}</Chip>
                <span className="min-w-0 flex-1 break-words text-fg-1">{e.text}</span>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

// ───────────────────────────── Hash compare

function HashCompareTool() {
  const [sets, setSets] = useState([
    { label: "List A", text: "" },
    { label: "List B", text: "" },
  ]);
  const hashSets: HashSet[] = useMemo(() => sets.map((s) => ({ label: s.label, values: parseHashList(s.text) })), [sets]);
  const result = useMemo(() => compareHashSets(hashSets), [hashSets]);

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <Panel title="Hash lists" meta="MD5, SHA-1, SHA-256 or SHA-512 — one per line, or separated by commas/whitespace. Non-hash tokens are ignored.">
        <div className="flex flex-col gap-3">
          {sets.map((s, i) => (
            <div key={i}>
              <div className="mb-1.5 flex items-center gap-2">
                <input className="input h-8 w-full max-w-xs text-sm" value={s.label} onChange={(e) => setSets((list) => list.map((x, k) => (k === i ? { ...x, label: e.target.value } : x)))} aria-label={`Set ${i + 1} label`} />
                <span className="mono text-xs text-fg-4">{hashSets[i]?.values.length ?? 0} hashes</span>
              </div>
              <textarea className="input mono h-28 w-full resize-y p-2 text-[11.5px]" placeholder="Paste hashes…" value={s.text} onChange={(e) => setSets((list) => list.map((x, k) => (k === i ? { ...x, text: e.target.value } : x)))} aria-label={`Set ${i + 1} content`} />
            </div>
          ))}
          <button type="button" className="btn btn-ghost btn-sm self-start" onClick={() => setSets((list) => [...list, { label: `List ${String.fromCharCode(65 + list.length)}`, text: "" }])}>
            + Add list
          </button>
        </div>
      </Panel>
      <Panel title="Comparison" meta={`${result.rows.length} unique values · ${result.inAll} in all ${result.setCount} lists · ${result.onlyOne} unique to one list`} bodyClassName="p-0">
        {!result.rows.length ? (
          <EmptyState icon={<Hash size={17} />} title="Nothing to compare yet" />
        ) : (
          <DataTable
            rows={result.rows}
            columns={[
              { key: "v", label: "Value", render: (r) => <Mono className="break-all text-fg-1">{r.value}</Mono>, sort: (r) => r.value },
              { key: "k", label: "Type", render: (r) => <Chip>{hashKind(r.value) ?? "?"}</Chip> },
              { key: "s", label: "Present in", render: (r) => <span className="flex flex-wrap gap-1">{r.sets.map((s) => <Chip key={s} tone="ice">{s}</Chip>)}</span> },
              { key: "c", label: "Count", render: (r) => <Mono className={r.count === result.setCount && result.setCount > 1 ? "text-err" : ""}>{r.count}</Mono>, sort: (r) => r.count, className: "text-right" },
            ]}
          />
        )}
      </Panel>
    </div>
  );
}

// ───────────────────────────── Process tree

function toTreeNode(n: ProcessNode): TreeNode {
  return { label: `${n.name} (${n.pid})`, value: n.commandLine ?? n.user, children: n.children.length ? n.children.map(toTreeNode) : undefined };
}

function ProcessTreeTool() {
  const [text, setText] = useState("");
  const result = useMemo(() => parseProcessListing(text), [text]);
  const roots = useMemo(() => [...result.roots, ...result.orphans].map(toTreeNode), [result]);

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <Panel title="Process listing" meta="A CSV/TSV table with pid, ppid and name columns, or Sysmon-style ProcessId / ParentProcessId / Image / CommandLine blocks.">
        <textarea className="input mono h-[420px] w-full resize-y p-2 text-[11.5px]" placeholder={"pid,ppid,name,commandline\n4,0,System,\n600,4,services.exe,\n…"} value={text} onChange={(e) => setText(e.target.value)} aria-label="Process listing" />
        {result.warnings.length > 0 && (
          <ul className="mt-2 flex flex-col gap-1 text-xs text-warn">
            {result.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        )}
      </Panel>
      <Panel title="Process tree" meta={result.total ? `${result.total} processes · ${result.format} format${result.orphans.length ? ` · ${result.orphans.length} with a parent outside this listing` : ""}` : undefined} bodyClassName="p-0">
        {!roots.length ? (
          <EmptyState icon={<GitBranch size={17} />} title="Nothing parsed yet" />
        ) : (
          <div className="max-h-[560px] overflow-auto p-2">
            <Tree nodes={roots} />
          </div>
        )}
      </Panel>
    </div>
  );
}

// ───────────────────────────── Event ID reference

function EventIdTool() {
  const [q, setQ] = useState("");
  const [channel, setChannel] = useState<string | "ALL">("ALL");
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return EVENT_ID_REFERENCE.filter((e) => (channel === "ALL" || e.channel === channel) && (!needle || String(e.id).includes(needle) || e.name.toLowerCase().includes(needle) || e.description.toLowerCase().includes(needle)));
  }, [q, channel]);

  return (
    <Panel bodyClassName="p-0">
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-3 py-2">
        <div className="relative">
          <Search size={12} className="pointer-events-none absolute top-1/2 left-2 -translate-y-1/2 text-fg-4" />
          <input className="input h-8 w-56 pl-7 text-sm" placeholder="Search ID, name, description…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search event IDs" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button type="button" className={cx("btn btn-sm", channel === "ALL" ? "btn-primary" : "btn-ghost")} onClick={() => setChannel("ALL")}>
            All
          </button>
          {EVENT_ID_CHANNELS.map((c) => (
            <button key={c} type="button" className={cx("btn btn-sm", channel === c ? "btn-primary" : "btn-ghost")} onClick={() => setChannel(c)}>
              {c}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-fg-4">{filtered.length} of {EVENT_ID_REFERENCE.length}</span>
      </div>
      <DataTable<EventIdEntry>
        rows={filtered}
        columns={[
          { key: "id", label: "ID", render: (e) => <Mono className="text-fg-1">{e.id}</Mono>, sort: (e) => e.id },
          { key: "c", label: "Channel", render: (e) => <span className="text-xs text-fg-3">{e.channel}</span> },
          { key: "n", label: "Name", render: (e) => <span className="text-fg-1">{e.name}</span> },
          { key: "d", label: "Description", render: (e) => <span className="max-w-xl text-xs text-fg-2">{e.description}</span> },
          { key: "a", label: "ATT&CK", render: (e) => <span className="flex flex-wrap gap-1">{e.attack?.map((a) => <AttackChip key={a} id={a} />)}</span> },
        ]}
      />
    </Panel>
  );
}
