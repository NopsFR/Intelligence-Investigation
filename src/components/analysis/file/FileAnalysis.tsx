"use client";

import { Binary, Download, FileSearch, RotateCcw, ScanSearch, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { MAX_ANALYSIS_BYTES, type FileReport } from "@/lib/analysis/analyze";
import { useInvestigate } from "@/lib/client/investigate";
import { useWorker } from "@/lib/client/worker";
import { cx } from "@/lib/client/cx";
import { SEVERITY_COLOR, TypeTag } from "@/components/ui/badges";
import { Tabs } from "@/components/ui/overlays";
import { CopyButton, EmptyState, ErrorNote, Panel, Stat } from "@/components/ui/primitives";
import { FileDrop, HexView, formatBytes, type HexHighlight } from "@/components/ui/workbench";
import { AttackChip, Chip, DataTable, EntropyMeter, EntropyProfile, LocalFindings, Mono, downloadJson } from "../common";
import { ElfHeaders, ElfSections, ElfSymbols, MachoView, PeExports, PeHeaders, PeImports, PeResources, PeSections, PeSignatureView } from "./FormatViews";
import { StringsView } from "./StringsView";

const createWorker = () => new Worker(new URL("../../../lib/analysis/file.worker.ts", import.meta.url), { type: "module" });

type State = { phase: "idle" } | { phase: "working"; name: string; size: number } | { phase: "done"; report: FileReport; bytes: Uint8Array } | { phase: "error"; name: string; message: string };

const REGION_COLORS = ["var(--color-ice)", "var(--color-sev-medium)", "var(--color-ok)", "#c9a0d8", "var(--color-sev-low)", "var(--color-sev-high)"];

function highlightsFor(r: FileReport): HexHighlight[] {
  const out: HexHighlight[] = [];
  if (r.pe) {
    const pe = r.pe;
    out.push({ start: 0, end: 0x40, label: "DOS header", color: "var(--color-fg-2)" });
    if (pe.rich) out.push({ start: pe.rich.offset, end: pe.rich.offset + pe.rich.size, label: "Rich header", color: "#c9a0d8" });
    out.push({ start: pe.headerOffsets.pe, end: pe.headerOffsets.optional, label: "PE signature + COFF header", color: "var(--color-signal-hi)" });
    out.push({ start: pe.headerOffsets.optional, end: pe.headerOffsets.sectionTable, label: "Optional header", color: "var(--color-sev-medium)" });
    out.push({ start: pe.headerOffsets.sectionTable, end: pe.headerOffsets.sectionTable + pe.sections.length * 40, label: "Section table", color: "var(--color-ok)" });
    pe.sections.forEach((s, i) => s.rawSize && out.push({ start: s.rawOffset, end: s.rawOffset + s.rawSize, label: `Section ${s.name}`, color: REGION_COLORS[i % REGION_COLORS.length] }));
    if (pe.overlay) out.push({ start: pe.overlay.offset, end: pe.overlay.offset + pe.overlay.size, label: "Overlay", color: "var(--color-sev-high)" });
    if (pe.signature.present) out.push({ start: pe.signature.offset, end: pe.signature.offset + pe.signature.size, label: "Certificate table", color: "var(--color-sev-low)" });
  } else if (r.elf) {
    out.push({ start: 0, end: r.elf.class === "ELF64" ? 64 : 52, label: "ELF header", color: "var(--color-signal-hi)" });
    r.elf.sections.forEach((s, i) => s.size && s.type !== "NOBITS" && s.offset && out.push({ start: s.offset, end: s.offset + s.size, label: `Section ${s.name}`, color: REGION_COLORS[i % REGION_COLORS.length] }));
  } else if (r.macho) {
    for (const sl of r.macho.slices) for (const [i, seg] of sl.segments.entries()) if (seg.filesize) out.push({ start: sl.offset + seg.fileoff, end: sl.offset + seg.fileoff + seg.filesize, label: `Segment ${seg.name}${r.macho.fat ? ` (${sl.cpu})` : ""}`, color: REGION_COLORS[i % REGION_COLORS.length] });
  }
  return out;
}

function regionsFor(r: FileReport) {
  if (r.pe) return [...r.pe.sections.filter((s) => s.rawSize).map((s) => ({ start: s.rawOffset, end: s.rawOffset + s.rawSize, label: s.name || "?" })), ...(r.pe.overlay ? [{ start: r.pe.overlay.offset, end: r.pe.overlay.offset + r.pe.overlay.size, label: "overlay" }] : [])];
  if (r.elf) return r.elf.sections.filter((s) => s.size > 512 && s.type !== "NOBITS" && s.offset).map((s) => ({ start: s.offset, end: s.offset + s.size, label: s.name }));
  if (r.macho) return r.macho.slices.flatMap((sl) => sl.segments.filter((s) => s.filesize).map((s) => ({ start: sl.offset + s.fileoff, end: sl.offset + s.fileoff + s.filesize, label: s.name })));
  return [];
}

export function FileAnalysis() {
  const [state, setState] = useState<State>({ phase: "idle" });
  const [tab, setTab] = useState("overview");
  const [focus, setFocus] = useState<number | undefined>(undefined);
  const run = useWorker<{ file: File }, { report: FileReport }>(createWorker);

  const onFile = useCallback(
    async (file: File, bytes: Uint8Array) => {
      setState({ phase: "working", name: file.name, size: file.size });
      setTab("overview");
      setFocus(undefined);
      try {
        const { report } = await run({ file });
        setState({ phase: "done", report, bytes });
      } catch (err) {
        setState({ phase: "error", name: file.name, message: err instanceof Error ? err.message : String(err) });
      }
    },
    [run]
  );

  const openHex = useCallback((offset: number) => {
    setFocus(offset);
    setTab("hex");
  }, []);

  if (state.phase !== "done") {
    return (
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="flex flex-col gap-3">
          <FileDrop
            onFile={onFile}
            maxBytes={MAX_ANALYSIS_BYTES}
            busy={state.phase === "working"}
            title={state.phase === "working" ? `Analysing ${state.name}` : "Drop a file to analyse"}
            description="Executables (PE, ELF, Mach-O), documents, archives, scripts or any binary. Hashes, file type, entropy, strings, structure, imports, signatures and capability indicators."
          />
          {state.phase === "error" && <ErrorNote title={`Could not analyse ${state.name}`}>{state.message}</ErrorNote>}
        </div>
        <Panel title="How this works">
          <ul className="flex flex-col gap-2.5 text-sm text-fg-2">
            <li className="flex gap-2.5">
              <ShieldCheck size={15} className="mt-0.5 shrink-0 text-ok" />
              <span>The file is read and parsed inside your browser, in a worker. It is never uploaded and never executed.</span>
            </li>
            <li className="flex gap-2.5">
              <Binary size={15} className="mt-0.5 shrink-0 text-fg-3" />
              <span>Parsers are bounds-checked and capped, so malformed or hostile files fail with an explanation instead of hanging the page.</span>
            </li>
            <li className="flex gap-2.5">
              <ScanSearch size={15} className="mt-0.5 shrink-0 text-fg-3" />
              <span>Only if you choose to, the SHA-256 is sent to the hash intelligence sources (MalwareBazaar, ThreatFox, YARAify, CIRCL, and VirusTotal when configured) through a normal investigation.</span>
            </li>
          </ul>
          <p className="mt-4 text-xs text-fg-4">Handle live malware on an isolated analysis machine. Static analysis cannot see what packed or encrypted code does at run time.</p>
        </Panel>
      </div>
    );
  }

  return <Report report={state.report} bytes={state.bytes} tab={tab} setTab={setTab} focus={focus} openHex={openHex} reset={() => setState({ phase: "idle" })} />;
}

function Report({ report: r, bytes, tab, setTab, focus, openHex, reset }: { report: FileReport; bytes: Uint8Array; tab: string; setTab: (t: string) => void; focus?: number; openHex: (o: number) => void; reset: () => void }) {
  const { start, pending } = useInvestigate();
  const highlights = useMemo(() => highlightsFor(r), [r]);
  const regions = useMemo(() => regionsFor(r), [r]);
  const worst = r.findings[0]?.severity;
  const counts = r.findings.reduce<Record<string, number>>((m, f) => ((m[f.severity] = (m[f.severity] ?? 0) + 1), m), {});

  const tabs = [
    { id: "overview", label: "Overview", count: r.findings.length },
    ...(r.pe
      ? [
          { id: "structure", label: "Headers" },
          { id: "sections", label: "Sections", count: r.pe.sections.length },
          { id: "imports", label: "Imports", count: r.pe.importCount },
          { id: "exports", label: "Exports", count: r.pe.exports.entries.length },
          { id: "resources", label: "Resources", count: r.pe.resources.length },
          { id: "signature", label: "Signature" },
        ]
      : []),
    ...(r.elf
      ? [
          { id: "structure", label: "Headers" },
          { id: "sections", label: "Sections", count: r.elf.sections.length },
          { id: "symbols", label: "Symbols", count: r.elf.imports.length + r.elf.exports.length },
        ]
      : []),
    ...(r.macho ? [{ id: "structure", label: "Mach-O" }] : []),
    { id: "strings", label: "Strings", count: r.strings.length },
    { id: "indicators", label: "Indicators", count: r.indicators.length },
    { id: "hex", label: "Hex" },
  ];

  return (
    <div className="flex flex-col gap-4">
      <section className="panel panel-ticks animate-rise">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-3 border-b border-line-1 p-[var(--panel-pad)]">
          <div className="min-w-0 flex-1">
            <div className="label mb-1 flex items-center gap-2">
              <span>Static analysis</span>
              <span className="text-fg-4">· {r.durationMs} ms · local</span>
            </div>
            <h2 className="display truncate text-xl text-fg-1" title={r.name}>
              {r.name}
            </h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-fg-3">
              <Chip tone="ice">{r.type.label}</Chip>
              <span className="mono">{r.type.mime}</span>
              <span>{formatBytes(r.size)}</span>
              {r.pe && <Chip>{`${r.pe.format} · ${r.pe.machineName}`}</Chip>}
              {r.elf && <Chip>{`${r.elf.class} · ${r.elf.machine}`}</Chip>}
              {r.macho && <Chip>{r.macho.slices.map((s) => s.cpu).join(" + ")}</Chip>}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="btn btn-primary" disabled={pending} onClick={() => void start(r.hashes.sha256, "QUICK", { type: "SHA256" })}>
              <FileSearch size={14} /> Investigate SHA-256
            </button>
            <button type="button" className="btn" onClick={() => downloadJson(`${r.name}.analysis.json`, { ...r, strings: r.strings.filter((s) => s.tags.length) })}>
              <Download size={14} /> Report
            </button>
            <button type="button" className="btn btn-ghost" onClick={reset}>
              <RotateCcw size={14} /> Another file
            </button>
          </div>
        </div>
        <div className="grid gap-px bg-line-1 sm:grid-cols-2 xl:grid-cols-4">
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Highest finding" value={worst ? <span style={{ color: SEVERITY_COLOR[worst] }}>{worst[0] + worst.slice(1).toLowerCase()}</span> : "None"} sub={Object.entries(counts).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(" · ") || "No rule matched"} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Entropy" value={<EntropyMeter value={r.entropy} width={90} />} sub={r.entropy > 7.2 ? "Compressed or encrypted content" : r.entropy < 1 ? "Mostly constant bytes" : "Mixed code / data"} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Strings" value={<span className="tabular">{r.strings.length.toLocaleString()}</span>} sub={`${r.strings.filter((s) => s.tags.length).length.toLocaleString()} tagged · ${r.indicators.length} network indicators`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat
              label="Signature"
              value={r.pe ? (r.pe.signature.present ? (r.pe.signature.digestMatches === false ? <span className="text-err">Digest mismatch</span> : r.pe.signature.signer?.subject.cn ?? "Signed") : "Unsigned") : r.macho ? (r.macho.slices.some((s) => s.signature) ? (r.macho.slices[0].signature?.teamId ? `Team ${r.macho.slices[0].signature.teamId}` : "Ad hoc") : "Unsigned") : "—"}
              sub={r.pe?.signature.present ? "Digest checked · chain not verified" : r.pe ? "No embedded Authenticode" : r.macho ? "Parsed · not verified" : "Not applicable to this type"}
            />
          </div>
        </div>
        <div className="border-t border-line-1 px-[var(--panel-pad)] py-3">
          <dl className="grid gap-x-4 gap-y-1 text-sm md:grid-cols-[64px_minmax(0,1fr)]">
            {(["md5", "sha1", "sha256", "sha512"] as const).map((k) => (
              <div key={k} className="contents">
                <dt className="label pt-0.5">{k === "sha1" ? "SHA-1" : k === "md5" ? "MD5" : k.toUpperCase().replace("SHA", "SHA-")}</dt>
                <dd className="flex min-w-0 items-center gap-1.5">
                  <Mono className="min-w-0 truncate text-fg-1">{r.hashes[k]}</Mono>
                  <CopyButton value={r.hashes[k]} label={`Copy ${k}`} />
                </dd>
              </div>
            ))}
            {r.pe?.imphash && (
              <div className="contents">
                <dt className="label pt-0.5">imphash</dt>
                <dd className="flex min-w-0 items-center gap-1.5">
                  <Mono className="truncate text-fg-2">{r.pe.imphash}</Mono>
                  <CopyButton value={r.pe.imphash} label="Copy imphash" />
                </dd>
              </div>
            )}
          </dl>
        </div>
      </section>

      <section className="panel">
        <Tabs items={tabs} value={tab} onChange={setTab} label="Analysis sections" className="px-2" />
        <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} key={tab} className="animate-fade">
          {tab === "overview" && (
            <div className="grid gap-px bg-line-1 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
              <div className="bg-ink-1">
                <LocalFindings findings={r.findings} />
              </div>
              <div className="flex flex-col gap-4 bg-ink-1 p-[var(--panel-pad)]">
                <div>
                  <h3 className="label mb-2">Entropy profile</h3>
                  <EntropyProfile profile={r.profile} size={r.size} regions={regions} onSelect={openHex} />
                </div>
                {r.capabilities.length > 0 && (
                  <div>
                    <h3 className="label mb-2">Capability indicators</h3>
                    <ul className="flex flex-col divide-y divide-line-1">
                      {r.capabilities.map((c) => (
                        <li key={c.id} className="py-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="h-2 w-2 rounded-[1px]" style={{ background: SEVERITY_COLOR[c.severity] }} aria-hidden />
                            <span className="text-sm text-fg-1">{c.title}</span>
                            {c.attack.map((a) => (
                              <AttackChip key={a} id={a} />
                            ))}
                          </div>
                          <p className="mono mt-1 text-[11px] text-fg-3">{c.matched.join(" · ")}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {r.apiCategories.length > 0 && (
                  <div>
                    <h3 className="label mb-2">Catalogued API use</h3>
                    <ul className="flex flex-col gap-1.5">
                      {r.apiCategories.map((c) => (
                        <li key={c.category} className="text-xs">
                          <span className="text-fg-2">{c.label}</span> <span className="mono text-fg-4">({c.functions.length})</span>
                          <div className="mono mt-0.5 text-[11px] text-fg-3">{c.functions.slice(0, 12).join(", ")}{c.functions.length > 12 ? " …" : ""}</div>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {r.embedded.length > 0 && (
                  <div>
                    <h3 className="label mb-2">Embedded content markers</h3>
                    <ul className="flex flex-col gap-1">
                      {r.embedded.slice(0, 20).map((e, i) => (
                        <li key={i} className="flex items-center gap-2 text-xs">
                          <button type="button" className="mono link" onClick={() => openHex(e.offset)}>
                            0x{e.offset.toString(16)}
                          </button>
                          <span className="text-fg-2">{e.kind}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {!r.pe && !r.elf && !r.macho && (
                  <p className="text-xs text-fg-3">{r.type.analyzer === "pcap" ? <>This is a packet capture — open it in the <Link className="link" href="/analysis/pcap">packet capture lab</Link>.</> : "No structural parser for this type; hashes, strings, entropy and indicators are still available."}</p>
                )}
              </div>
            </div>
          )}
          {tab === "structure" && r.pe && <PeHeaders pe={r.pe} />}
          {tab === "structure" && r.elf && <ElfHeaders elf={r.elf} />}
          {tab === "structure" && r.macho && <MachoView macho={r.macho} />}
          {tab === "sections" && r.pe && <PeSections pe={r.pe} onOffset={openHex} />}
          {tab === "sections" && r.elf && <ElfSections elf={r.elf} onOffset={openHex} />}
          {tab === "imports" && r.pe && <PeImports pe={r.pe} />}
          {tab === "exports" && r.pe && <PeExports pe={r.pe} />}
          {tab === "resources" && r.pe && <PeResources pe={r.pe} onOffset={openHex} />}
          {tab === "signature" && r.pe && <PeSignatureView pe={r.pe} />}
          {tab === "symbols" && r.elf && <ElfSymbols elf={r.elf} />}
          {tab === "strings" && <StringsView strings={r.strings} truncated={r.stringsTruncated} onOffset={openHex} />}
          {tab === "indicators" && <Indicators report={r} onOffset={openHex} />}
          {tab === "hex" && (
            <div className="p-3">
              <HexView bytes={bytes} highlights={highlights} focus={focus} height={560} />
              {highlights.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px]">
                  {highlights.slice(0, 24).map((h, i) => (
                    <button key={i} type="button" className="mono inline-flex items-center gap-1.5 text-fg-3 hover:text-fg-1" onClick={() => openHex(h.start)}>
                      <span className="h-2 w-2 rounded-[1px]" style={{ background: h.color }} aria-hidden />
                      {h.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function Indicators({ report, onOffset }: { report: FileReport; onOffset: (o: number) => void }) {
  const { start, pending } = useInvestigate();
  if (!report.indicators.length) return <EmptyState title="No network indicators">No domains, IP addresses, URLs or email addresses were found in the strings. Encrypted or packed content hides them; so does building them at run time.</EmptyState>;
  return (
    <div>
      <p className="border-b border-line-1 px-3 py-2 text-xs text-fg-3">Found in strings and validated by the same detector as the search bar. Presence in a binary is not malicious by itself — certificate authorities, XML namespaces and documentation links are common.</p>
      <DataTable
        rows={report.indicators}
        columns={[
          { key: "t", label: "Type", render: (i) => <TypeTag type={i.type} /> },
          { key: "v", label: "Indicator", render: (i) => <Mono className="break-all text-fg-1">{i.value}</Mono>, sort: (i) => i.value },
          { key: "n", label: "Seen", render: (i) => <Mono>{i.occurrences}</Mono>, sort: (i) => i.occurrences, className: "text-right" },
          {
            key: "o",
            label: "Offsets",
            render: (i) => (
              <span className="flex flex-wrap gap-1">
                {i.offsets.slice(0, 3).map((o) => (
                  <button key={o} type="button" className={cx("mono link text-[11px]")} onClick={() => onOffset(o)}>
                    0x{o.toString(16)}
                  </button>
                ))}
              </span>
            ),
          },
          {
            key: "a",
            label: "",
            render: (i) => (
              <button type="button" className="btn btn-ghost btn-sm" disabled={pending} onClick={() => void start(i.value, "QUICK", { type: i.type })}>
                Investigate
              </button>
            ),
          },
        ]}
      />
    </div>
  );
}
