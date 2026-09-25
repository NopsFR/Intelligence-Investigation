"use client";

import { useMemo, useState } from "react";
import { API_CATEGORY_LABEL, apiInfo } from "@/lib/analysis/apis";
import type { ElfAnalysis } from "@/lib/analysis/elf";
import type { MachoAnalysis } from "@/lib/analysis/macho";
import type { PeAnalysis } from "@/lib/analysis/pe";
import { cx } from "@/lib/client/cx";
import { Mark } from "@/components/investigation/views/common";
import { formatBytes } from "@/components/ui/workbench";
import { CertificateCard } from "../CertificateCard";
import { Chip, DataTable, EntropyMeter, KV, Mono } from "../common";

const hx = (n: number) => `0x${n.toString(16)}`;

function Block({ title, children, meta }: { title: string; children: React.ReactNode; meta?: React.ReactNode }) {
  return (
    <section className="border-b border-line-1 px-[var(--panel-pad)] py-4 last:border-b-0">
      <h3 className="label mb-2 flex items-center gap-2">
        {title}
        {meta && <span className="normal-case tracking-normal text-fg-4">{meta}</span>}
      </h3>
      {children}
    </section>
  );
}

// ───────────────────────────── PE

export function PeHeaders({ pe }: { pe: PeAnalysis }) {
  const has = (f: string) => pe.dllCharacteristics.includes(f);
  return (
    <div>
      <Block title="File header">
        <KV
          rows={[
            ["Format", `${pe.format}${pe.isDll ? " DLL" : pe.isDriver ? " driver" : " executable"}${pe.isDotNet ? " · .NET" : ""}`],
            ["Machine", pe.machineName],
            ["Subsystem", pe.subsystem],
            ["Linker timestamp", pe.reproducible ? <span key="t">{pe.timestampIso ?? "0"} <span className="text-fg-3">(reproducible build: this is a content hash, not a date)</span></span> : pe.timestampIso ?? "0 (not set)"],
            ["Characteristics", <span key="c" className="flex flex-wrap gap-1">{pe.characteristics.map((c) => <Chip key={c}>{c}</Chip>)}</span>],
          ]}
        />
      </Block>
      <Block title="Optional header">
        <KV
          rows={[
            ["Entry point", <Mono key="e">{`${hx(pe.entryPoint)} (${pe.entrySection ?? "outside sections"})`}</Mono>],
            ["Image base", <Mono key="b">{pe.imageBase}</Mono>],
            ["Size of image", <Mono key="s">{`${hx(pe.sizeOfImage)} (${formatBytes(pe.sizeOfImage)})`}</Mono>],
            ["Linker / OS version", `${pe.linkerVersion} / ${pe.osVersion}`],
            ["Checksum", <Mono key="ck">{`stored ${hx(pe.checksum.stored)} · computed ${hx(pe.checksum.computed)}${pe.checksum.stored === 0 ? " (not set)" : pe.checksum.stored === pe.checksum.computed ? " ✓" : " ✗"}`}</Mono>],
            ["imphash", pe.imphash ? <Mono key="i">{pe.imphash}{!pe.imphashExact && <span className="text-fg-3"> (approximate: ordinal imports from ws2_32 / wsock32 / oleaut32)</span>}</Mono> : "No imports"],
          ]}
        />
      </Block>
      <Block title="Mitigations">
        <div className="flex flex-wrap gap-x-5 gap-y-2">
          <Mark state={has("DYNAMIC_BASE") ? "pass" : "fail"}>ASLR</Mark>
          {pe.is64 && <Mark state={has("HIGH_ENTROPY_VA") ? "pass" : "warn"}>High-entropy ASLR</Mark>}
          <Mark state={has("NX_COMPAT") ? "pass" : "fail"}>DEP / NX</Mark>
          <Mark state={has("GUARD_CF") || pe.loadConfig?.cfgInstrumented ? "pass" : "warn"}>Control Flow Guard</Mark>
          <Mark state={pe.loadConfig?.securityCookie ? "pass" : "warn"}>Stack cookie (/GS)</Mark>
          {!pe.is64 && <Mark state={has("NO_SEH") ? "info" : pe.loadConfig?.sehTable ? "pass" : "warn"}>SafeSEH{has("NO_SEH") ? " (no SEH)" : ""}</Mark>}
          <Mark state={has("FORCE_INTEGRITY") ? "pass" : "info"}>Force integrity</Mark>
        </div>
      </Block>
      {Object.keys(pe.version).length > 0 && (
        <Block title="Version information">
          <KV rows={Object.entries(pe.version).map(([k, v]) => [k, v])} />
        </Block>
      )}
      {(pe.debug.length > 0 || pe.tlsCallbacks.length > 0) && (
        <Block title="Debug & TLS">
          <KV
            rows={[
              ...pe.debug.map((d, i): [string, React.ReactNode] => [d.type, d.pdb ? <Mono key={i}>{`${d.pdb}${d.guid ? `  {${d.guid}} age ${d.age}` : ""}`}</Mono> : "present"]),
              ...pe.tlsCallbacks.map((c, i): [string, React.ReactNode] => [`TLS callback ${i + 1}`, <Mono key={`t${i}`}>{`${c.va} (${c.section ?? "outside sections"})`}</Mono>]),
            ]}
          />
        </Block>
      )}
      {pe.manifest && (
        <Block title="Manifest" meta={pe.manifest.executionLevel ? `requestedExecutionLevel = ${pe.manifest.executionLevel}` : undefined}>
          <pre className="mono max-h-64 overflow-auto rounded-[2px] bg-ink-0 p-3 text-[11px] whitespace-pre-wrap text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{pe.manifest.raw.slice(0, 8000)}</pre>
        </Block>
      )}
      {pe.rich && (
        <Block title="Rich header" meta={`${pe.rich.entries.length} tool entries · checksum ${pe.rich.checksumValid ? "valid" : "INVALID (edited after linking)"} · hash ${pe.rich.hash}`}>
          <p className="mb-2 max-w-3xl text-xs text-fg-3">Undocumented MSVC linker record of the tools (product ID and build) that produced each object. Useful for clustering samples built on the same toolchain.</p>
          <DataTable
            rows={pe.rich.entries}
            columns={[
              { key: "p", label: "Product ID", render: (e) => <Mono>{`${e.productId} (${hx(e.productId)})`}</Mono>, sort: (e) => e.productId },
              { key: "b", label: "Build", render: (e) => <Mono>{e.build}</Mono>, sort: (e) => e.build },
              { key: "c", label: "Count", render: (e) => <Mono>{e.count}</Mono>, sort: (e) => e.count, className: "text-right" },
            ]}
          />
        </Block>
      )}
      <Block title="Data directories">
        <DataTable
          rows={pe.directories.filter((d) => d.rva || d.size)}
          columns={[
            { key: "n", label: "Directory", render: (d) => d.name },
            { key: "r", label: "RVA / offset", render: (d) => <Mono>{hx(d.rva)}</Mono> },
            { key: "s", label: "Size", render: (d) => <Mono>{d.size.toLocaleString()}</Mono>, className: "text-right" },
          ]}
        />
      </Block>
      {pe.anomalies.length > 0 && (
        <Block title="Anomalies">
          <ul className="list-disc pl-5 text-sm text-fg-2">
            {pe.anomalies.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </Block>
      )}
    </div>
  );
}

export function PeSections({ pe, onOffset }: { pe: PeAnalysis; onOffset: (o: number) => void }) {
  return (
    <DataTable
      rows={pe.sections}
      columns={[
        { key: "n", label: "Name", render: (s) => <span className="flex items-center gap-2"><Mono className="text-fg-1">{s.name || "(empty)"}</Mono>{s.packer && <Chip tone="warn">{s.packer}</Chip>}{s.name === pe.entrySection && <Chip tone="ice">entry</Chip>}</span> },
        { key: "va", label: "Virtual addr / size", render: (s) => <Mono>{`${hx(s.virtualAddress)} / ${hx(s.virtualSize)}`}</Mono>, sort: (s) => s.virtualAddress },
        { key: "raw", label: "Raw offset / size", render: (s) => <button type="button" className="mono link text-[12px]" onClick={() => onOffset(s.rawOffset)}>{`${hx(s.rawOffset)} / ${hx(s.rawSize)}`}</button>, sort: (s) => s.rawOffset },
        { key: "p", label: "Access", render: (s) => <Mono className={cx(s.writable && s.executable && "text-sev-high")}>{`${s.readable ? "R" : "-"}${s.writable ? "W" : "-"}${s.executable ? "X" : "-"}`}</Mono> },
        { key: "e", label: "Entropy", render: (s) => <EntropyMeter value={s.entropy} />, sort: (s) => s.entropy },
        { key: "m", label: "MD5", render: (s) => <Mono className="text-fg-3">{s.md5}</Mono> },
      ]}
    />
  );
}

export function PeImports({ pe }: { pe: PeAnalysis }) {
  const [onlyNotable, setOnlyNotable] = useState(false);
  const [q, setQ] = useState("");
  const libs = useMemo(
    () =>
      pe.imports
        .map((imp) => ({
          ...imp,
          functions: imp.functions.filter((f) => {
            const name = f.name ?? `#${f.ordinal}`;
            if (onlyNotable && !(f.name && apiInfo(f.name))) return false;
            return !q || name.toLowerCase().includes(q.toLowerCase()) || imp.dll.toLowerCase().includes(q.toLowerCase());
          }),
        }))
        .filter((i) => i.functions.length),
    [pe.imports, onlyNotable, q]
  );
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-3 py-2">
        <input className="input h-8 w-full max-w-xs text-sm" placeholder="Filter DLLs or functions" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter imports" />
        <label className="flex items-center gap-2 text-xs text-fg-2">
          <input type="checkbox" checked={onlyNotable} onChange={(e) => setOnlyNotable(e.target.checked)} /> Only catalogued capability APIs
        </label>
        <span className="mono ml-auto text-[11px] text-fg-3">
          {pe.imports.length} libraries · {pe.importCount} functions
        </span>
      </div>
      {!libs.length && <p className="px-3 py-6 text-sm text-fg-3">{pe.imports.length ? "No imports match the filter." : "This file has no import table."}</p>}
      <div className="grid gap-px bg-line-1 md:grid-cols-2 xl:grid-cols-3">
        {libs.map((imp) => (
          <div key={`${imp.dll}-${imp.delayed}`} className="bg-ink-1 p-3">
            <div className="mb-1.5 flex items-center gap-2">
              <Mono className="font-semibold text-fg-1">{imp.dll}</Mono>
              {imp.delayed && <Chip>delay-load</Chip>}
              <span className="mono ml-auto text-[11px] text-fg-4">{imp.functions.length}</span>
            </div>
            <ul className="max-h-72 overflow-auto">
              {imp.functions.map((f, i) => {
                const info = f.name ? apiInfo(f.name) : undefined;
                return (
                  <li key={i} className="flex items-baseline gap-2 py-[2px]" title={info ? `${API_CATEGORY_LABEL[info.category]} — ${info.note}` : undefined}>
                    <Mono className={cx(info ? "text-sev-medium" : "text-fg-2")}>{f.name ?? `ordinal ${f.ordinal}`}</Mono>
                    {info && <span className="truncate text-[11px] text-fg-4">{API_CATEGORY_LABEL[info.category]}</span>}
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

export function PeExports({ pe }: { pe: PeAnalysis }) {
  return (
    <div>
      {pe.exports.dllName && <p className="border-b border-line-1 px-3 py-2 text-xs text-fg-3">Export name <Mono className="text-fg-1">{pe.exports.dllName}</Mono></p>}
      <DataTable
        rows={pe.exports.entries}
        empty="No exports."
        columns={[
          { key: "o", label: "Ordinal", render: (e) => <Mono>{e.ordinal}</Mono>, sort: (e) => e.ordinal },
          { key: "n", label: "Name", render: (e) => <Mono className="text-fg-1">{e.name ?? "(by ordinal)"}</Mono>, sort: (e) => e.name ?? "" },
          { key: "r", label: "RVA / forwarder", render: (e) => <Mono>{e.forwarder ? `→ ${e.forwarder}` : hx(e.rva)}</Mono> },
        ]}
      />
    </div>
  );
}

export function PeResources({ pe, onOffset }: { pe: PeAnalysis; onOffset: (o: number) => void }) {
  return (
    <DataTable
      rows={pe.resources}
      empty="No resources."
      columns={[
        { key: "t", label: "Type", render: (r) => <Mono className="text-fg-1">{r.type}</Mono>, sort: (r) => r.type },
        { key: "n", label: "Name", render: (r) => <Mono>{r.name}</Mono> },
        { key: "l", label: "Lang", render: (r) => <Mono>{hx(r.language)}</Mono> },
        { key: "s", label: "Size", render: (r) => <Mono>{r.size.toLocaleString()}</Mono>, sort: (r) => r.size, className: "text-right" },
        { key: "e", label: "Entropy", render: (r) => (r.entropy !== null ? <EntropyMeter value={r.entropy} width={48} /> : "—"), sort: (r) => r.entropy ?? 0 },
        { key: "d", label: "Content", render: (r) => (r.detected ? <Chip tone={r.detected.family === "executable" ? "err" : "neutral"}>{r.detected.label}</Chip> : "") },
        { key: "o", label: "Offset", render: (r) => (r.offset !== null ? <button type="button" className="mono link text-[12px]" onClick={() => onOffset(r.offset!)}>{hx(r.offset)}</button> : "—") },
      ]}
    />
  );
}

export function PeSignatureView({ pe }: { pe: PeAnalysis }) {
  const s = pe.signature;
  if (!s.present) return <p className="px-[var(--panel-pad)] py-6 text-sm text-fg-3">No embedded Authenticode signature. Windows system files are usually catalogue-signed instead, which cannot be checked from the file alone.</p>;
  return (
    <div>
      <Block title="Authenticode">
        <KV
          rows={[
            ["Status", s.parsed ? (s.digestMatches === true ? <Mark key="m" state="pass">Signed digest matches this file</Mark> : s.digestMatches === false ? <Mark key="m" state="fail">File changed after signing — digest mismatch</Mark> : <Mark key="m" state="info">Digest not checked ({s.digestAlgorithm})</Mark>) : <Mark key="m" state="fail">Could not parse: {s.error}</Mark>],
            ["Program", s.programName],
            ["More info", s.moreInfoUrl],
            ["Timestamp", s.signingTime ?? (s.parsed ? "No countersignature timestamp" : undefined)],
            ["Digest", s.signedDigest && <Mono key="d" className="break-all">{`${s.digestAlgorithm} ${s.signedDigest}`}</Mono>],
            ["Certificate table", <Mono key="c">{`offset ${hx(s.offset)}, ${s.size.toLocaleString()} bytes`}</Mono>],
            ["Nested signatures", s.nestedSignatures || undefined],
          ]}
        />
        <p className="mt-3 max-w-3xl text-xs text-fg-3">
          The digest check proves the file is byte-for-byte what was signed. The signature itself, the certificate chain and revocation were <strong className="text-fg-2">not</strong> verified — that needs a trust store (signtool verify /pa, or Get-AuthenticodeSignature on Windows).
        </p>
      </Block>
      {s.certificates.length > 0 && (
        <Block title="Certificates" meta={`${s.certificates.length} embedded`}>
          <div className="grid gap-3 lg:grid-cols-2">
            {s.certificates.map((c, i) => (
              <CertificateCard key={i} cert={c} role={s.signer && c.serial === s.signer.serial ? "Signer" : c.isCA ? "CA" : undefined} />
            ))}
          </div>
        </Block>
      )}
    </div>
  );
}

// ───────────────────────────── ELF

export function ElfHeaders({ elf }: { elf: ElfAnalysis }) {
  const c = elf.checksec;
  return (
    <div>
      <Block title="ELF header">
        <KV
          rows={[
            ["Class", `${elf.class}, ${elf.endianness}-endian`],
            ["Type", elf.type],
            ["Machine", elf.machine],
            ["OS / ABI", elf.osAbi],
            ["Entry point", <Mono key="e">{elf.entry}</Mono>],
            ["Interpreter", elf.interpreter && <Mono key="i">{elf.interpreter}</Mono>],
            ["Build ID", elf.buildId && <Mono key="b">{elf.buildId}</Mono>],
            ["SONAME", elf.soname],
            ["Linking", elf.staticallyLinked ? "Static" : elf.needed.length ? "Dynamic" : "—"],
            ["Symbols", elf.stripped ? "Stripped (no .symtab)" : `${elf.symbols.length.toLocaleString()} symbols${elf.symbolsTruncated ? " (truncated)" : ""}`],
            ["Packer", elf.packer],
          ]}
        />
      </Block>
      <Block title="Hardening (checksec)">
        <div className="flex flex-wrap gap-x-5 gap-y-2">
          <Mark state={c.nx ? "pass" : "fail"}>NX stack</Mark>
          <Mark state={c.pie === "yes" ? "pass" : c.pie === "shared-object" ? "info" : "fail"}>{c.pie === "shared-object" ? "Shared object (PIC)" : "PIE"}</Mark>
          <Mark state={c.relro === "full" ? "pass" : c.relro === "partial" ? "warn" : "fail"}>RELRO: {c.relro}</Mark>
          <Mark state={c.canary ? "pass" : "warn"}>Stack canary</Mark>
          <Mark state={c.fortify ? "pass" : "info"}>FORTIFY_SOURCE{c.fortify ? ` (${c.fortifiedFunctions.length})` : ""}</Mark>
          <Mark state={c.rpath ? "warn" : "pass"}>{c.rpath ? "RPATH/RUNPATH set" : "No RPATH"}</Mark>
        </div>
      </Block>
      {(elf.needed.length > 0 || elf.rpath || elf.runpath) && (
        <Block title="Dynamic dependencies">
          <div className="flex flex-wrap gap-1.5">
            {elf.needed.map((n) => (
              <Chip key={n}>{n}</Chip>
            ))}
          </div>
          {(elf.rpath || elf.runpath) && <p className="mono mt-2 text-[12px] text-fg-2">{elf.rpath && `RPATH ${elf.rpath}`} {elf.runpath && `RUNPATH ${elf.runpath}`}</p>}
        </Block>
      )}
      <Block title="Program headers">
        <DataTable
          rows={elf.segments}
          columns={[
            { key: "t", label: "Type", render: (s) => <Mono className="text-fg-1">{s.type}</Mono> },
            { key: "o", label: "Offset", render: (s) => <Mono>{hx(s.offset)}</Mono> },
            { key: "v", label: "Virtual addr", render: (s) => <Mono>{s.vaddr}</Mono> },
            { key: "f", label: "File / mem size", render: (s) => <Mono>{`${hx(s.fileSize)} / ${hx(s.memSize)}`}</Mono> },
            { key: "p", label: "Flags", render: (s) => <Mono className={cx(s.flags === "RWX" && "text-sev-high")}>{s.flags}</Mono> },
          ]}
        />
      </Block>
      {elf.notes.length > 0 && (
        <Block title="Notes">
          <KV rows={elf.notes.map((n) => [`${n.owner} type ${n.type}`, <Mono key={`${n.owner}${n.type}`} className="break-all">{n.description}</Mono>])} />
        </Block>
      )}
    </div>
  );
}

export function ElfSections({ elf, onOffset }: { elf: ElfAnalysis; onOffset: (o: number) => void }) {
  return (
    <DataTable
      rows={elf.sections}
      empty="No section headers (the section table is stripped)."
      columns={[
        { key: "i", label: "#", render: (s) => <Mono className="text-fg-4">{s.index}</Mono> },
        { key: "n", label: "Name", render: (s) => <Mono className="text-fg-1">{s.name || "—"}</Mono>, sort: (s) => s.name },
        { key: "t", label: "Type", render: (s) => <Mono>{s.type}</Mono> },
        { key: "a", label: "Address", render: (s) => <Mono>{s.addr}</Mono> },
        { key: "o", label: "Offset", render: (s) => <button type="button" className="mono link text-[12px]" onClick={() => onOffset(s.offset)}>{hx(s.offset)}</button>, sort: (s) => s.offset },
        { key: "s", label: "Size", render: (s) => <Mono>{s.size.toLocaleString()}</Mono>, sort: (s) => s.size, className: "text-right" },
        { key: "f", label: "Flags", render: (s) => <Mono>{s.flags}</Mono> },
        { key: "e", label: "Entropy", render: (s) => (s.entropy !== null ? <EntropyMeter value={s.entropy} width={48} /> : "—"), sort: (s) => s.entropy ?? 0 },
      ]}
    />
  );
}

export function ElfSymbols({ elf }: { elf: ElfAnalysis }) {
  const [view, setView] = useState<"imports" | "exports" | "relocations">("imports");
  const [q, setQ] = useState("");
  const f = (name: string) => !q || name.toLowerCase().includes(q.toLowerCase());
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-line-1 px-3 py-2">
        {(["imports", "exports", "relocations"] as const).map((v) => (
          <button key={v} type="button" className={cx("btn btn-sm", view === v ? "btn-primary" : "btn-ghost")} onClick={() => setView(v)}>
            {v} <span className="mono text-[10.5px] opacity-70">{v === "imports" ? elf.imports.length : v === "exports" ? elf.exports.length : elf.relocations.length}</span>
          </button>
        ))}
        <input className="input ml-auto h-8 w-full max-w-xs text-sm" placeholder="Filter symbols" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter symbols" />
      </div>
      {view === "relocations" ? (
        <DataTable
          rows={elf.relocations.filter((r) => f(r.symbol))}
          empty="No relocations."
          columns={[
            { key: "s", label: "Section", render: (r) => <Mono>{r.section}</Mono> },
            { key: "o", label: "Offset", render: (r) => <Mono>{r.offset}</Mono> },
            { key: "t", label: "Type", render: (r) => <Mono>{r.type}</Mono> },
            { key: "y", label: "Symbol", render: (r) => <Mono className="text-fg-1">{r.symbol || "—"}</Mono> },
            { key: "a", label: "Addend", render: (r) => <Mono>{r.addend ?? ""}</Mono> },
          ]}
        />
      ) : (
        <DataTable
          rows={(view === "imports" ? elf.imports : elf.exports).filter((s) => f(s.name))}
          empty={view === "imports" ? "No undefined (imported) symbols." : "No exported symbols."}
          columns={[
            { key: "n", label: "Symbol", render: (s) => <Mono className="text-fg-1">{s.name}</Mono>, sort: (s) => s.name },
            { key: "v", label: "Version", render: (s) => <Mono className="text-fg-3">{s.version ?? ""}</Mono> },
            { key: "t", label: "Type", render: (s) => <Mono>{s.type}</Mono> },
            { key: "b", label: "Bind", render: (s) => <Mono>{s.bind}</Mono> },
            { key: "a", label: "Value", render: (s) => <Mono>{s.value}</Mono> },
          ]}
        />
      )}
    </div>
  );
}

// ───────────────────────────── Mach-O

export function MachoView({ macho }: { macho: MachoAnalysis }) {
  const [i, setI] = useState(0);
  const slice = macho.slices[Math.min(i, macho.slices.length - 1)];
  if (!slice) return <p className="p-4 text-sm text-fg-3">No readable architecture slices.</p>;
  const sig = slice.signature;
  return (
    <div>
      {macho.fat && (
        <div className="flex flex-wrap items-center gap-1.5 border-b border-line-1 px-3 py-2">
          <span className="label mr-2">Universal binary</span>
          {macho.slices.map((s, k) => (
            <button key={k} type="button" className={cx("btn btn-sm", k === i ? "btn-primary" : "btn-ghost")} onClick={() => setI(k)}>
              {s.cpu}
            </button>
          ))}
        </div>
      )}
      <Block title="Header">
        <KV
          rows={[
            ["CPU", `${slice.cpu}${slice.is64 ? " (64-bit)" : ""}`],
            ["File type", slice.fileType],
            ["Flags", <span key="f" className="flex flex-wrap gap-1">{slice.flags.map((f) => <Chip key={f}>{f}</Chip>)}</span>],
            ["Platform", slice.platform && `${slice.platform} ≥ ${slice.minOs} (SDK ${slice.sdk})`],
            ["UUID", slice.uuid && <Mono key="u">{slice.uuid}</Mono>],
            ["Entry offset", slice.entryOffset !== undefined && <Mono key="e">{hx(slice.entryOffset)}</Mono>],
            ["Dynamic linker", slice.dylinker],
            ["Encrypted", slice.encrypted ? "Yes (FairPlay)" : undefined],
          ]}
        />
      </Block>
      <Block title="Code signature">
        {sig ? (
          <>
            <KV
              rows={[
                ["Identifier", sig.identifier],
                ["Team ID", sig.teamId ?? (sig.adhoc ? "none (ad hoc)" : undefined)],
                ["Flags", sig.flags.join(", ") || "none"],
                ["Hash", sig.hashType],
                ["Certificates", sig.hasCms ? `${sig.certificates.length} in CMS blob` : "none (no CMS signature)"],
                ["Error", sig.error],
              ]}
            />
            {sig.notableEntitlements.length > 0 && (
              <ul className="mt-3 flex flex-col gap-1">
                {sig.notableEntitlements.map((e) => (
                  <li key={e.key} className="text-sm">
                    <Mono className="text-sev-medium">{e.key}</Mono> <span className="text-fg-3">— {e.note}</span>
                  </li>
                ))}
              </ul>
            )}
            {sig.certificates.length > 0 && (
              <div className="mt-3 grid gap-3 lg:grid-cols-2">
                {sig.certificates.map((c, k) => (
                  <CertificateCard key={k} cert={c} />
                ))}
              </div>
            )}
            {sig.entitlements && <pre className="mono mt-3 max-h-64 overflow-auto rounded-[2px] bg-ink-0 p-3 text-[11px] whitespace-pre-wrap text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{sig.entitlements.slice(0, 12000)}</pre>}
            <p className="mt-3 text-xs text-fg-3">Parsed, not verified. Use codesign --verify --deep and spctl --assess for trust and notarisation.</p>
          </>
        ) : (
          <p className="text-sm text-fg-3">No LC_CODE_SIGNATURE load command.</p>
        )}
      </Block>
      <Block title="Linked libraries" meta={`${slice.libraries.length}`}>
        <DataTable
          rows={slice.libraries}
          columns={[
            { key: "n", label: "Library", render: (l) => <Mono className="text-fg-1">{l.name}</Mono> },
            { key: "k", label: "Kind", render: (l) => <Mono>{l.kind}</Mono> },
            { key: "v", label: "Version", render: (l) => <Mono>{l.currentVersion}</Mono> },
          ]}
        />
        {slice.rpaths.length > 0 && <p className="mono mt-2 text-[12px] text-fg-2">rpath {slice.rpaths.join(" : ")}</p>}
      </Block>
      <Block title="Segments">
        <DataTable
          rows={slice.segments.flatMap((s) => [{ ...s, isSection: false, label: s.name, size: s.filesize, entropy: null as number | null }, ...s.sections.map((x) => ({ ...s, isSection: true, label: `  ${x.segment},${x.name}`, size: x.size, fileoff: x.offset, entropy: x.entropy }))])}
          columns={[
            { key: "n", label: "Segment / section", render: (s) => <Mono className={s.isSection ? "text-fg-2" : "font-semibold text-fg-1"}>{s.label}</Mono> },
            { key: "o", label: "File offset", render: (s) => <Mono>{hx(s.fileoff)}</Mono> },
            { key: "s", label: "Size", render: (s) => <Mono>{s.size.toLocaleString()}</Mono>, className: "text-right" },
            { key: "p", label: "Prot (init/max)", render: (s) => (s.isSection ? "" : <Mono className={cx(s.initprot.includes("w") && s.initprot.includes("x") && "text-sev-high")}>{`${s.initprot} / ${s.maxprot}`}</Mono>) },
            { key: "e", label: "Entropy", render: (s) => (s.entropy !== null ? <EntropyMeter value={s.entropy} width={48} /> : "") },
          ]}
        />
      </Block>
      <Block title="Symbols" meta={`${slice.imports.length} imported · ${slice.exports.length} exported`}>
        <div className="grid gap-3 md:grid-cols-2">
          <ul className="max-h-72 overflow-auto rounded-[2px] bg-ink-0 p-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
            {slice.imports.slice(0, 3000).map((s) => (
              <li key={s} className="mono text-[11.5px] text-fg-2">{s}</li>
            ))}
          </ul>
          <ul className="max-h-72 overflow-auto rounded-[2px] bg-ink-0 p-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
            {slice.exports.slice(0, 3000).map((s) => (
              <li key={s} className="mono text-[11.5px] text-fg-2">{s}</li>
            ))}
          </ul>
        </div>
      </Block>
    </div>
  );
}
