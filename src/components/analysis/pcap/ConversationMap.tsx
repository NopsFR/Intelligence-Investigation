"use client";

import { useMemo, useState } from "react";
import type { CaptureReport } from "@/lib/pcap/analyze";
import { isPublicAddress } from "@/lib/observables/ip";
import { cx } from "@/lib/client/cx";

// Three-column evidence map: local hosts → remote addresses → names seen for
// those addresses (DNS answers, TLS SNI, HTTP Host). Every edge says where it
// came from.

interface Node {
  id: string;
  label: string;
  column: 0 | 1 | 2;
  weight: number;
  external?: boolean;
}

interface Edge {
  from: string;
  to: string;
  weight: number;
  label: string;
}

export function ConversationMap({ report, limit = 18 }: { report: CaptureReport; limit?: number }) {
  const [hover, setHover] = useState<string | null>(null);
  const { nodes, edges, height } = useMemo(() => {
    const hostBytes = new Map<string, number>();
    const pair = new Map<string, { bytes: number; apps: Set<string> }>();
    for (const f of report.flows) {
      hostBytes.set(f.client, (hostBytes.get(f.client) ?? 0) + f.bytes);
      const k = `${f.client}|${f.server}`;
      const e = pair.get(k) ?? { bytes: 0, apps: new Set() };
      e.bytes += f.bytes;
      if (f.app) e.apps.add(f.app);
      pair.set(k, e);
    }
    const servers = new Map<string, number>();
    for (const [k, v] of pair) servers.set(k.split("|")[1], (servers.get(k.split("|")[1]) ?? 0) + v.bytes);
    const topServers = [...servers.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([s]) => s);
    const topSet = new Set(topServers);
    const clients = [...hostBytes.entries()].filter(([c]) => [...pair.keys()].some((k) => k.startsWith(`${c}|`) && topSet.has(k.split("|")[1]))).sort((a, b) => b[1] - a[1]).slice(0, limit).map(([c]) => c);

    const names = new Map<string, { server: string; via: string }[]>();
    const addName = (name: string, server: string, via: string) => {
      if (!topSet.has(server)) return;
      const list = names.get(name) ?? [];
      if (!list.some((x) => x.server === server)) list.push({ server, via });
      names.set(name, list);
    };
    for (const t of report.tls) if (t.sni) addName(t.sni, t.server, "TLS SNI");
    for (const h of report.http) if (!/^\d/.test(h.host)) addName(h.host.replace(/:\d+$/, ""), h.server, "HTTP Host");
    for (const q of report.dns) for (const a of q.answers) {
      const [type, value] = a.split(" ");
      if (type === "A" || type === "AAAA") addName(q.name.replace(/\.$/, ""), value, `DNS ${type}`);
    }
    const nameList = [...names.keys()].slice(0, limit * 2);

    const nodes: Node[] = [
      ...clients.map((c) => ({ id: `c:${c}`, label: c, column: 0 as const, weight: hostBytes.get(c) ?? 0, external: isPublicAddress(c) })),
      ...topServers.map((s) => ({ id: `s:${s}`, label: s, column: 1 as const, weight: servers.get(s) ?? 0, external: isPublicAddress(s) })),
      ...nameList.map((n) => ({ id: `n:${n}`, label: n, column: 2 as const, weight: 1 })),
    ];
    const edges: Edge[] = [];
    for (const [k, v] of pair) {
      const [c, s] = k.split("|");
      if (clients.includes(c) && topSet.has(s)) edges.push({ from: `c:${c}`, to: `s:${s}`, weight: v.bytes, label: [...v.apps].slice(0, 3).join(", ") });
    }
    for (const n of nameList) for (const { server, via } of names.get(n)!) edges.push({ from: `s:${server}`, to: `n:${n}`, weight: 1, label: via });
    const rowsNeeded = Math.max(clients.length, topServers.length, nameList.length);
    return { nodes, edges, height: Math.max(160, rowsNeeded * 30 + 40) };
  }, [report, limit]);

  if (!edges.length) return <p className="px-3 py-6 text-sm text-fg-3">No TCP or UDP conversations to map.</p>;

  const W = 1000;
  const colX = [150, 500, 850];
  const pos = new Map<string, { x: number; y: number }>();
  for (const col of [0, 1, 2] as const) {
    const list = nodes.filter((n) => n.column === col);
    const gap = (height - 40) / Math.max(1, list.length);
    list.forEach((n, i) => pos.set(n.id, { x: colX[col], y: 20 + gap * (i + 0.5) }));
  }
  const maxW = Math.max(...edges.map((e) => e.weight));
  const related = (id: string) => hover === null || hover === id || edges.some((e) => (e.from === hover && e.to === id) || (e.to === hover && e.from === id));

  return (
    <figure className="m-0">
      <svg viewBox={`0 0 ${W} ${height}`} className="block w-full" role="img" aria-label="Conversation map: local hosts, remote addresses and the names they were reached by">
        {["Hosts (clients)", "Remote addresses", "Names (DNS / SNI / Host)"].map((t, i) => (
          <text key={t} x={colX[i]} y={12} textAnchor="middle" className="fill-fg-4" style={{ font: "600 10px var(--font-sans)", letterSpacing: "0.08em", textTransform: "uppercase" }}>
            {t}
          </text>
        ))}
        {edges.map((e, i) => {
          const a = pos.get(e.from)!;
          const b = pos.get(e.to)!;
          const on = hover === null || hover === e.from || hover === e.to;
          const w = 0.75 + (e.weight / maxW) * 3.5;
          return (
            <g key={i} opacity={on ? 1 : 0.12} className="transition-opacity duration-200">
              <path d={`M${a.x + 60},${a.y} C${(a.x + b.x) / 2},${a.y} ${(a.x + b.x) / 2},${b.y} ${b.x - 60},${b.y}`} fill="none" stroke={e.from.startsWith("s:") ? "var(--color-line-4)" : "color-mix(in srgb, var(--color-ice) 55%, transparent)"} strokeWidth={w}>
                <title>{e.label}</title>
              </path>
              {hover !== null && on && e.label && (
                <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} textAnchor="middle" className="fill-fg-2" style={{ font: "10px var(--font-mono)" }}>
                  {e.label}
                </text>
              )}
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos.get(n.id)!;
          const on = related(n.id);
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`} opacity={on ? 1 : 0.25} className="cursor-pointer transition-opacity duration-200" onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}>
              <rect x={-60} y={-10} width={120} height={20} rx={2} fill="var(--color-ink-2)" stroke={n.external ? "var(--color-sev-medium)" : "var(--color-line-3)"} />
              <text textAnchor="middle" y={3.5} className={cx(n.column === 2 ? "fill-fg-1" : "fill-fg-2")} style={{ font: "10.5px var(--font-mono)" }}>
                {n.label.length > 19 ? `${n.label.slice(0, 18)}…` : n.label}
                <title>{n.label}</title>
              </text>
            </g>
          );
        })}
      </svg>
      <figcaption className="mt-1 flex flex-wrap gap-x-4 px-3 text-[11px] text-fg-4">
        <span>Edge width = bytes exchanged</span>
        <span className="text-[color-mix(in_srgb,var(--color-sev-medium)_80%,var(--color-fg-3))]">Amber outline = public address</span>
        <span>Hover a node to trace it; edge labels show the evidence (application, DNS answer, SNI, Host header)</span>
      </figcaption>
    </figure>
  );
}
