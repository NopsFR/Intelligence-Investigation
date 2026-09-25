"use client";

import { ArrowRight, Regex } from "lucide-react";
import Link from "next/link";
import { MAGIC_BYTES, REGEX_PATTERNS } from "@/lib/knowledge/reference";
import { CopyButton, Panel } from "@/components/ui/primitives";
import { Mono } from "../analysis/common";

export function ReferenceHub() {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Link href="/toolbox" className="panel panel-ticks group flex items-center justify-between p-4 transition-colors hover:bg-ink-2">
          <div>
            <div className="text-sm font-medium text-fg-1 group-hover:underline">TCP flags, HTTP status, ports &amp; protocols</div>
            <div className="text-xs text-fg-3">In the Toolbox &quot;References&quot; tool</div>
          </div>
          <ArrowRight size={14} className="text-fg-4" />
        </Link>
        <Link href="/dfir" className="panel panel-ticks group flex items-center justify-between p-4 transition-colors hover:bg-ink-2">
          <div>
            <div className="text-sm font-medium text-fg-1 group-hover:underline">Windows Event ID reference</div>
            <div className="text-xs text-fg-3">In the DFIR workbench</div>
          </div>
          <ArrowRight size={14} className="text-fg-4" />
        </Link>
      </div>

      <Panel title="File signatures (magic bytes)" meta={`${MAGIC_BYTES.length}`} bodyClassName="p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line-1 text-left text-xs text-fg-4">
              <th className="px-[var(--panel-pad)] py-2 font-normal">Format</th>
              <th className="px-2 py-2 font-normal">Bytes (hex)</th>
              <th className="px-[var(--panel-pad)] py-2 font-normal">Offset</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-1">
            {MAGIC_BYTES.map((m) => (
              <tr key={m.format}>
                <td className="px-[var(--panel-pad)] py-1.5 align-top text-fg-2">{m.format}</td>
                <td className="px-2 py-1.5 align-top">
                  <Mono className="text-fg-1">{m.hex}</Mono>
                </td>
                <td className="px-[var(--panel-pad)] py-1.5 align-top text-xs text-fg-4">{m.offset}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-4">
          The File &amp; binary analyzer identifies file types from content this way automatically — this table is for manual triage (hex editors, <Mono className="text-fg-4">xxd</Mono>).
        </p>
      </Panel>

      <Panel title="Regex patterns for security work" meta={<Regex size={13} className="text-fg-4" />} bodyClassName="p-0">
        <ul className="divide-y divide-line-1">
          {REGEX_PATTERNS.map((r) => (
            <li key={r.name} className="flex flex-col flex-wrap gap-1 px-[var(--panel-pad)] py-2.5 sm:flex-row sm:items-start sm:gap-4">
              <div className="text-sm text-fg-2 sm:w-[220px] sm:shrink-0">{r.name}</div>
              <div className="flex min-w-0 flex-1 items-start gap-1">
                <Mono className="min-w-0 flex-1 break-all text-xs text-fg-1">{r.pattern}</Mono>
                <CopyButton value={r.pattern} label={`Copy ${r.name} pattern`} />
              </div>
              {r.note && <p className="text-xs text-fg-4 sm:basis-full sm:pl-[220px]">{r.note}</p>}
            </li>
          ))}
        </ul>
        <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-4">
          Try these against real text in the Toolbox&apos;s Regex tester, or the Decoder lab for chained extraction.
        </p>
      </Panel>
    </div>
  );
}
