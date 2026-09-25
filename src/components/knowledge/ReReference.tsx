"use client";

import { useState } from "react";
import { API_CATEGORY_LABEL, CATALOGUE } from "@/lib/analysis/apis";
import {
  ARM64_INSTRUCTIONS,
  ARM64_REGISTERS,
  CALLING_CONVENTIONS,
  LINUX_AARCH64_SYSCALL_NOTE,
  LINUX_X86_64_SYSCALLS,
  X86_64_INSTRUCTIONS,
  X86_64_REGISTERS,
} from "@/lib/knowledge/re";
import { Tabs } from "@/components/ui/overlays";
import { Panel } from "@/components/ui/primitives";
import { Mono } from "../analysis/common";

const TABS = [
  { id: "registers", label: "Registers" },
  { id: "instructions", label: "Instructions" },
  { id: "calling", label: "Calling conventions" },
  { id: "syscalls", label: "Syscalls" },
  { id: "winapi", label: "Windows APIs" },
];

export function ReReference() {
  const [tab, setTab] = useState("registers");
  return (
    <div className="flex flex-col gap-4">
      <Tabs label="Reverse engineering topic" value={tab} onChange={setTab} items={TABS} />
      {tab === "registers" && <RegistersTab />}
      {tab === "instructions" && <InstructionsTab />}
      {tab === "calling" && <CallingTab />}
      {tab === "syscalls" && <SyscallsTab />}
      {tab === "winapi" && <WinApiTab />}
    </div>
  );
}

function RegistersTab() {
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="x86-64" bodyClassName="p-0">
        <table className="w-full text-sm">
          <tbody className="divide-y divide-line-1">
            {X86_64_REGISTERS.map((r) => (
              <tr key={r.name}>
                <td className="px-[var(--panel-pad)] py-2 align-top">
                  <Mono className="text-fg-1">{r.name}</Mono>
                </td>
                <td className="px-2 py-2 align-top text-xs text-fg-4">{r.width}</td>
                <td className="px-[var(--panel-pad)] py-2 align-top text-fg-2">{r.purpose}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      <Panel title="ARM64 / AArch64" bodyClassName="p-0">
        <table className="w-full text-sm">
          <tbody className="divide-y divide-line-1">
            {ARM64_REGISTERS.map((r) => (
              <tr key={r.name}>
                <td className="px-[var(--panel-pad)] py-2 align-top">
                  <Mono className="text-fg-1">{r.name}</Mono>
                </td>
                <td className="px-2 py-2 align-top text-xs text-fg-4">{r.width}</td>
                <td className="px-[var(--panel-pad)] py-2 align-top text-fg-2">{r.purpose}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}

function InstructionsTab() {
  return (
    <div className="flex flex-col gap-4">
      <Panel title="x86-64" bodyClassName="p-0">
        <ul className="divide-y divide-line-1">
          {X86_64_INSTRUCTIONS.map((i) => (
            <li key={i.mnemonic} className="px-[var(--panel-pad)] py-3">
              <div className="flex flex-wrap items-baseline gap-2">
                <Mono className="text-sm font-semibold text-fg-1">{i.mnemonic}</Mono>
                <Mono className="text-xs text-fg-4">{i.syntax}</Mono>
              </div>
              <p className="mt-1 text-sm text-fg-3">{i.description}</p>
              {i.flags && <p className="mt-0.5 text-xs text-fg-4">Flags: {i.flags}</p>}
            </li>
          ))}
        </ul>
      </Panel>
      <Panel title="ARM64 / AArch64" bodyClassName="p-0">
        <ul className="divide-y divide-line-1">
          {ARM64_INSTRUCTIONS.map((i) => (
            <li key={i.mnemonic} className="px-[var(--panel-pad)] py-3">
              <div className="flex flex-wrap items-baseline gap-2">
                <Mono className="text-sm font-semibold text-fg-1">{i.mnemonic}</Mono>
                <Mono className="text-xs text-fg-4">{i.syntax}</Mono>
              </div>
              <p className="mt-1 text-sm text-fg-3">{i.description}</p>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}

function CallingTab() {
  return (
    <div className="flex flex-col gap-4">
      {CALLING_CONVENTIONS.map((c) => (
        <Panel key={c.name} title={c.name} meta={c.platforms} bodyClassName="p-0">
          <dl className="grid grid-cols-1 gap-x-6 gap-y-0 px-[var(--panel-pad)] py-2 sm:grid-cols-2">
            {[
              ["Integer/pointer args", c.intArgs],
              ["Float/vector args", c.floatArgs],
              ["Return value", c.returnReg],
              ["Caller-saved", c.callerSaved],
              ["Callee-saved", c.calleeSaved],
              ["Stack cleanup", c.stackCleanup],
            ].map(([label, value]) => (
              <div key={label} className="grid grid-cols-[140px_minmax(0,1fr)] items-start gap-3 border-b border-line-1 py-2 last:border-0">
                <dt className="text-xs text-fg-3">{label}</dt>
                <dd className="mono text-xs text-fg-1">{value}</dd>
              </div>
            ))}
          </dl>
        </Panel>
      ))}
    </div>
  );
}

function SyscallsTab() {
  return (
    <div className="flex flex-col gap-4">
      <Panel title="Linux x86-64 (curated subset)" meta={`${LINUX_X86_64_SYSCALLS.length}`} bodyClassName="p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line-1 text-left text-xs text-fg-4">
              <th className="px-[var(--panel-pad)] py-2 font-normal">#</th>
              <th className="px-2 py-2 font-normal">Name</th>
              <th className="px-[var(--panel-pad)] py-2 font-normal">Arguments</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-1">
            {LINUX_X86_64_SYSCALLS.map((s) => (
              <tr key={s.number}>
                <td className="px-[var(--panel-pad)] py-1.5 align-top">
                  <Mono className="text-fg-4">{s.number}</Mono>
                </td>
                <td className="px-2 py-1.5 align-top">
                  <Mono className="text-fg-1">{s.name}</Mono>
                </td>
                <td className="px-[var(--panel-pad)] py-1.5 align-top text-xs text-fg-3">{s.args}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-4">Number goes in RAX; call via the SYSCALL instruction. This is a curated subset (~450 syscalls exist in total) covering the ones most relevant to behavioral/malware analysis.</p>
      </Panel>
      <Panel title="AArch64">
        <p className="text-sm text-fg-3">{LINUX_AARCH64_SYSCALL_NOTE}</p>
      </Panel>
    </div>
  );
}

function WinApiTab() {
  const entries = Object.entries(CATALOGUE).sort(([a], [b]) => a.localeCompare(b));
  return (
    <Panel title="Notable Windows APIs" meta={`${entries.length}`} bodyClassName="p-0">
      <ul className="divide-y divide-line-1">
        {entries.map(([name, info]) => (
          <li key={name} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-[var(--panel-pad)] py-2.5">
            <Mono className="text-sm text-fg-1">{name}</Mono>
            <span className="text-xs text-fg-4">{API_CATEGORY_LABEL[info.category]}</span>
            <span className="text-sm text-fg-3">{info.note}</span>
          </li>
        ))}
      </ul>
      <p className="border-t border-line-1 px-[var(--panel-pad)] py-2.5 text-xs text-fg-4">The same catalogue used by the File &amp; binary analyzer to annotate imports — a single import is informational; combinations become findings there.</p>
    </Panel>
  );
}
