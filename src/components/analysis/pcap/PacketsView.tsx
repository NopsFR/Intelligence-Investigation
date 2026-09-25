"use client";

import { CircleHelp, Filter, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { CaptureReport, PacketRow } from "@/lib/pcap/analyze";
import type { LayerNode } from "@/lib/pcap/dissect";
import { FILTER_FIELDS } from "@/lib/pcap/filter";
import { cx } from "@/lib/client/cx";
import { Drawer } from "@/components/ui/overlays";
import { HexView, Tree, useVirtual, type TreeNode } from "@/components/ui/workbench";

export type PcapCall = <T>(payload: Record<string, unknown>) => Promise<T>;

const MARK_COLOR: Record<NonNullable<PacketRow["mark"]>, string> = {
  syn: "var(--color-fg-4)",
  rst: "var(--color-err)",
  err: "var(--color-err)",
  dns: "var(--color-ice)",
  tls: "#c9a0d8",
  http: "var(--color-ok)",
  icmp: "var(--color-sev-medium)",
  arp: "var(--color-sev-low)",
  dhcp: "var(--color-sev-low)",
};

const QUICK = ["dns", "http", "tls", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "tcp.flags.reset == 1", "!(arp || dns || icmp)", "frame.len > 1000"];

function toTree(nodes: LayerNode[], onSelect: (r: [number, number] | undefined) => void): TreeNode[] {
  return nodes.map((n) => ({ label: n.label, value: n.value, onSelect: () => onSelect(n.range), children: n.children ? toTree(n.children, onSelect) : undefined }));
}

export function PacketsView({ report, call, filter, setFilter, onFollow }: { report: CaptureReport; call: PcapCall; filter: string; setFilter: (f: string) => void; onFollow: (stream: number) => void }) {
  const [draft, setDraft] = useState(filter);
  const [matches, setMatches] = useState<Set<number> | null>(null);
  const [error, setError] = useState<{ message: string; position: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const [detail, setDetail] = useState<{ layers: LayerNode[]; bytes: Uint8Array; stream?: number; malformed?: string } | null>(null);
  const [range, setRange] = useState<[number, number] | undefined>(undefined);
  const [help, setHelp] = useState(false);

  const apply = async (expr: string) => {
    setFilter(expr);
    setDraft(expr);
    if (!expr.trim()) {
      setMatches(null);
      setError(null);
      return;
    }
    setBusy(true);
    try {
      const res = await call<{ matches: number[] | null; error?: string; position?: number }>({ op: "filter", expr });
      if (res.error) setError({ message: res.error, position: res.position ?? 0 });
      else {
        setError(null);
        setMatches(new Set(res.matches));
      }
    } finally {
      setBusy(false);
    }
  };

  const rows = useMemo(() => (matches ? report.rows.filter((r) => matches.has(r.n)) : report.rows), [report.rows, matches]);
  const { ref: listRef, start, end, total } = useVirtual(rows.length, 24, 20);

  useEffect(() => {
    if (selected === null) return;
    let live = true;
    void call<{ layers: LayerNode[]; bytes: Uint8Array; stream?: number; malformed?: string }>({ op: "packet", n: selected }).then((d) => {
      if (live) {
        setDetail(d);
        setRange(undefined);
      }
    });
    return () => {
      live = false;
    };
  }, [selected, call]);

  const tree = useMemo(() => (detail ? toTree(detail.layers, setRange) : []), [detail]);

  return (
    <div>
      <form
        className="flex flex-wrap items-center gap-2 border-b border-line-1 px-3 py-2"
        onSubmit={(e) => {
          e.preventDefault();
          void apply(draft);
        }}
      >
        <div className="relative min-w-[260px] flex-1">
          <Filter size={13} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-fg-4" />
          <input
            className={cx("input mono h-8 w-full pl-8 text-[12px]", error ? "border-err" : matches ? "border-[color-mix(in_srgb,var(--color-ok)_60%,var(--color-line-3))]" : "")}
            placeholder='Display filter — e.g. ip.addr == 10.0.0.0/8 && tls.sni contains "cdn"'
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            aria-label="Display filter"
            aria-invalid={!!error}
            spellCheck={false}
          />
        </div>
        <button type="submit" className="btn btn-sm" disabled={busy}>
          {busy ? "Filtering…" : "Apply"}
        </button>
        {filter && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => void apply("")}>
            <X size={12} /> Clear
          </button>
        )}
        <button type="button" className="btn btn-ghost btn-sm btn-icon" aria-label="Filter reference" onClick={() => setHelp(true)}>
          <CircleHelp size={14} />
        </button>
        <span className="mono ml-auto text-[11px] text-fg-3 tabular">
          {rows.length.toLocaleString()} {matches ? `of ${report.rows.length.toLocaleString()} ` : ""}packets{report.rowsTruncated ? ` (first ${report.rows.length.toLocaleString()} listed)` : ""}
        </span>
      </form>
      {error && (
        <p className="mono border-b border-line-1 bg-[color-mix(in_srgb,var(--color-err)_7%,transparent)] px-3 py-1.5 pl-[42px] text-[12px] whitespace-pre text-err" role="alert">
          {draft}
          <br />
          {" ".repeat(error.position)}^ {error.message}
        </p>
      )}
      <div className="flex flex-wrap gap-1.5 border-b border-line-1 px-3 py-1.5">
        {QUICK.map((q) => (
          <button key={q} type="button" className={cx("mono rounded-[2px] px-1.5 py-0.5 text-[11px] transition-colors", filter === q ? "bg-ink-4 text-fg-1" : "text-fg-3 hover:bg-ink-2 hover:text-fg-1")} onClick={() => void apply(q)}>
            {q}
          </button>
        ))}
      </div>

      <div className="flex flex-col">
        <div className="min-w-0">
          <div className="mono grid grid-cols-[64px_84px_minmax(0,1fr)_minmax(0,1fr)_70px_56px] gap-2 border-b border-line-1 px-3 py-1.5 text-[10.5px] tracking-wide text-fg-4 uppercase lg:grid-cols-[64px_84px_150px_150px_70px_56px_minmax(0,1fr)]">
            <span>No.</span>
            <span>Time</span>
            <span>Source</span>
            <span>Destination</span>
            <span>Proto</span>
            <span className="text-right">Len</span>
            <span className="hidden lg:block">Info</span>
          </div>
          <div ref={listRef} className="relative overflow-auto" style={{ height: detail ? 380 : 560 }} role="listbox" aria-label="Packets">
            <div style={{ height: total, position: "relative" }}>
              {rows.slice(start, end).map((r, k) => {
                const i = start + k;
                const active = r.n === selected;
                return (
                  <button
                    key={r.n}
                    type="button"
                    role="option"
                    aria-selected={active}
                    onClick={() => setSelected(r.n)}
                    className={cx("mono absolute right-0 left-0 grid grid-cols-[64px_84px_minmax(0,1fr)_minmax(0,1fr)_70px_56px] items-center gap-2 px-3 text-left text-[11.5px] lg:grid-cols-[64px_84px_150px_150px_70px_56px_minmax(0,1fr)]", active ? "bg-ink-4 text-fg-1" : "text-fg-2 hover:bg-ink-2")}
                    style={{ top: i * 24, height: 24, boxShadow: r.mark ? `inset 2px 0 0 ${MARK_COLOR[r.mark]}` : undefined }}
                  >
                    <span className="text-fg-4 tabular">{r.n}</span>
                    <span className="tabular">{r.t.toFixed(6)}</span>
                    <span className="truncate" title={r.src}>{r.src}</span>
                    <span className="truncate" title={r.dst}>{r.dst}</span>
                    <span className="truncate" style={r.mark ? { color: MARK_COLOR[r.mark] } : undefined}>{r.proto}</span>
                    <span className="text-right tabular">{r.len}</span>
                    <span className="hidden truncate text-fg-3 lg:block" title={r.info}>{r.info}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
        <div className="min-w-0 border-t border-line-1">
          {!detail ? (
            <p className="px-4 py-6 text-center text-sm text-fg-3">Select a packet to see its layers and bytes.</p>
          ) : (
            <div className="flex flex-col">
              <div className="flex items-center gap-2 border-b border-line-1 px-3 py-1.5">
                <span className="label">Packet {selected}</span>
                {detail.malformed && <span className="text-xs text-err">Malformed: {detail.malformed}</span>}
                {detail.stream !== undefined && (
                  <button type="button" className="btn btn-ghost btn-sm ml-auto" onClick={() => onFollow(detail.stream!)}>
                    Follow stream {detail.stream}
                  </button>
                )}
              </div>
              <div className="grid lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                <div className="max-h-[300px] overflow-auto border-b border-line-1 py-1 lg:border-r lg:border-b-0">
                  <Tree nodes={tree} />
                </div>
                <div className="min-w-0 p-2">
                  <HexView bytes={detail.bytes} height={276} highlights={range ? [{ start: range[0], end: range[1], label: "Selected field" }] : []} focus={range?.[0]} />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <Drawer open={help} onClose={() => setHelp(false)} title="Display filter reference" subtitle="Wireshark-style subset, evaluated locally">
        <div className="flex flex-col gap-4 text-sm">
          <p className="text-fg-2">
            Combine with <code className="mono">&&</code> <code className="mono">||</code> <code className="mono">!</code> (or <code className="mono">and or not</code>) and parentheses. Operators: <code className="mono">== != &gt; &lt; &gt;= &lt;= contains matches in</code>. A bare field tests presence. <code className="mono">contains</code> and <code className="mono">matches</code> ignore case.
          </p>
          <ul className="mono flex flex-col gap-1 rounded-[2px] bg-ink-0 p-3 text-[11.5px] text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
            <li>ip.addr == 192.168.1.0/24 && !dns</li>
            <li>tcp.port in {"{"}22 3389 5985{"}"}</li>
            <li>tls.sni matches &quot;\.(top|xyz)$&quot;</li>
            <li>http.request.method == POST && http.host contains &quot;.&quot;</li>
            <li>dns.flags.rcode == NXDOMAIN</li>
            <li>tcp.stream == 4</li>
          </ul>
          <table className="table">
            <tbody>
              {FILTER_FIELDS.map((f) => (
                <tr key={f.field}>
                  <td className="mono text-[11.5px] text-fg-1">{f.field}</td>
                  <td className="text-xs text-fg-3">{f.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Drawer>
    </div>
  );
}

export function FollowStream({ stream, call, onClose }: { stream: number | null; call: PcapCall; onClose: () => void }) {
  const [data, setData] = useState<{ chunks: { dir: "client" | "server"; text: string; frame: number }[]; truncated: boolean } | null>(null);
  const [view, setView] = useState<"both" | "client" | "server">("both");
  useEffect(() => {
    if (stream === null) return;
    let live = true;
    void call<{ chunks: { dir: "client" | "server"; text: string; frame: number }[]; truncated: boolean }>({ op: "stream", stream }).then((d) => live && setData(d));
    return () => {
      live = false;
      setData(null);
    };
  }, [stream, call]);
  const bytes = data?.chunks.reduce((n, c) => n + c.text.length, 0) ?? 0;
  return (
    <Drawer open={stream !== null} onClose={onClose} title={`Stream ${stream ?? ""}`} subtitle="Payload in arrival order · credentials and cookies masked" width={820}>
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
        {(["both", "client", "server"] as const).map((v) => (
          <button key={v} type="button" className={cx("btn btn-sm", view === v ? "btn-primary" : "btn-ghost")} onClick={() => setView(v)}>
            {v === "both" ? "Both directions" : v === "client" ? "Client → server" : "Server → client"}
          </button>
        ))}
        <span className="ml-auto text-fg-3">
          <span className="text-[#e39a9a]">client</span> · <span className="text-[#9ab8e3]">server</span> · {bytes.toLocaleString()} bytes{data?.truncated ? " (first 1 MB)" : ""}
        </span>
      </div>
      {!data ? (
        <p className="text-sm text-fg-3">Reassembling…</p>
      ) : !data.chunks.length ? (
        <p className="text-sm text-fg-3">This stream carries no payload (handshake or control packets only).</p>
      ) : (
        <pre className="mono max-h-[70vh] overflow-auto rounded-[2px] bg-ink-0 p-3 text-[11.5px] leading-[17px] whitespace-pre-wrap break-all shadow-[inset_0_0_0_1px_var(--color-line-1)]">
          {data.chunks
            .filter((c) => view === "both" || c.dir === view)
            .map((c, i) => (
              <span key={i} className={c.dir === "client" ? "text-[#e39a9a]" : "text-[#9ab8e3]"}>
                {c.text.length > 200_000 ? `${c.text.slice(0, 200_000)}\n… (${(c.text.length - 200_000).toLocaleString()} more bytes)\n` : c.text}
              </span>
            ))}
        </pre>
      )}
    </Drawer>
  );
}
