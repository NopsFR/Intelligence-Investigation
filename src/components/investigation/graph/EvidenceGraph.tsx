"use client";

import "@xyflow/react/dist/style.css";
import { Background, BackgroundVariant, Handle, Position, ReactFlow, ReactFlowProvider, useReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";
import { Crosshair, Focus, Maximize2, Minus, Plus, Radar, X } from "lucide-react";
import { memo, useCallback, useEffect, useMemo, useState } from "react";
import type { InvestigationRecord, NodeType } from "@/lib/core/types";
import { useCatalog } from "@/lib/client/catalog";
import { cx } from "@/lib/client/cx";
import { useInvestigate } from "@/lib/client/investigate";
import { Prov } from "@/components/ui/badges";
import { CopyButton } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";
import { buildGraph, NODE_STYLE, PIVOTABLE, RELATION_LABELS, ROOT_NODE_TYPE, type GraphEdge, type GraphNode } from "./model";

type SimNode = SimulationNodeDatum & { id: string; root: boolean; r: number };

/** Approximate half-width of a rendered chip, so collisions respect wide labels. */
function radiusOf(n: GraphNode): number {
  const text = n.label && n.type !== "domain" && n.type !== "ip" ? n.label : n.value;
  const chars = Math.min(text.length, n.root ? 36 : 29);
  return Math.min(n.root ? 140 : 115, 24 + chars * 3.4) + 10;
}

interface EntityData extends Record<string, unknown> {
  node: GraphNode;
  dim: boolean;
  active: boolean;
  fresh: boolean;
}

const EntityNode = memo(function EntityNode({ data }: NodeProps<Node<EntityData>>) {
  const { node, dim, active, fresh } = data;
  const style = NODE_STYLE[node.type];
  const text = node.label && node.type !== "domain" && node.type !== "ip" ? `${node.label}` : node.value;
  return (
    <div
      className={cx(
        "group flex items-center gap-1.5 rounded-[3px] border bg-ink-1 py-1 pr-2 pl-1 shadow-[0_2px_10px_rgba(0,0,0,0.35)] transition-[opacity,border-color,box-shadow,transform] duration-200",
        fresh && "animate-rise",
        node.root ? "border-signal" : active ? "border-fg-2" : "border-line-3",
        dim ? "opacity-[0.18]" : "opacity-100",
        active && "shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-ice)_20%,transparent),0_4px_18px_rgba(0,0,0,0.45)]"
      )}
      style={{ maxWidth: node.root ? 260 : 210 }}
      title={`${style.label}: ${node.value}${node.label ? ` (${node.label})` : ""}`}
    >
      <Handle type="target" position={Position.Left} className="!h-1 !w-1 !min-w-0 !border-0 !bg-transparent" isConnectable={false} />
      <span className="mono grid h-[18px] min-w-[22px] place-items-center rounded-[2px] px-1 text-[9px] font-semibold" style={{ color: style.color, background: `color-mix(in srgb, ${style.color} 14%, transparent)` }}>
        {style.glyph}
      </span>
      <span className={cx("mono truncate text-[11px]", node.root ? "font-semibold text-fg-1" : "text-fg-2")}>{text}</span>
      <Handle type="source" position={Position.Right} className="!h-1 !w-1 !min-w-0 !border-0 !bg-transparent" isConnectable={false} />
    </div>
  );
});

const nodeTypes = { entity: EntityNode };

function layout(nodes: GraphNode[], edges: GraphEdge[], previous: Map<string, { x: number; y: number }>) {
  const sim: SimNode[] = nodes.map((n) => {
    const prev = previous.get(n.key);
    return { id: n.key, root: n.root, r: radiusOf(n), x: prev?.x ?? (n.root ? 0 : (Math.random() - 0.5) * 200), y: prev?.y ?? (n.root ? 0 : (Math.random() - 0.5) * 200), fx: n.root ? 0 : undefined, fy: n.root ? 0 : undefined };
  });
  // New nodes start beside an already-placed neighbour so arrivals read as growth, not a reshuffle.
  const byId = new Map(sim.map((s) => [s.id, s]));
  for (const e of edges) {
    const s = byId.get(e.source)!;
    const t = byId.get(e.target)!;
    if (!previous.has(t.id) && previous.has(s.id)) {
      t.x = (s.x ?? 0) + (Math.random() - 0.5) * 60;
      t.y = (s.y ?? 0) + (Math.random() - 0.5) * 60;
    }
  }
  const links: SimulationLinkDatum<SimNode>[] = edges.map((e) => ({ source: e.source, target: e.target }));
  const simulation = forceSimulation(sim)
    .force("link", forceLink<SimNode, SimulationLinkDatum<SimNode>>(links).id((d) => d.id).distance((l) => 70 + (l.source as SimNode).r + (l.target as SimNode).r * 0.6).strength(0.5))
    .force("charge", forceManyBody().strength(-420))
    .force("collide", forceCollide<SimNode>((d) => d.r).strength(0.9).iterations(2))
    .force("x", forceX(0).strength(0.04))
    .force("y", forceY(0).strength(0.06))
    .stop();
  const ticks = previous.size ? 140 : 320;
  for (let i = 0; i < ticks; i++) simulation.tick();
  return new Map(sim.map((s) => [s.id, { x: s.x ?? 0, y: s.y ?? 0 }]));
}

function GraphCanvas({ inv, height }: { inv: InvestigationRecord; height: number }) {
  const { fitView, zoomIn, zoomOut } = useReactFlow();
  const { name } = useCatalog();
  const { start } = useInvestigate();
  const [hover, setHover] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [focus, setFocus] = useState(false);
  const [hidden, setHidden] = useState<Set<NodeType>>(new Set());
  const [layoutState, setLayoutState] = useState<{ placed: Map<string, { x: number; y: number }>; fresh: Set<string> }>({ placed: new Map(), fresh: new Set() });

  const graph = useMemo(() => buildGraph(inv.relationships, { type: ROOT_NODE_TYPE[inv.observableType], value: inv.normalizedObservable }), [inv.relationships, inv.observableType, inv.normalizedObservable]);
  // Layout is incremental: existing entities keep their place, arrivals grow from their neighbours.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- derive the next layout from the previous one
    setLayoutState((prev) => ({ placed: layout(graph.nodes, graph.edges, prev.placed), fresh: new Set(graph.nodes.filter((n) => prev.placed.size > 0 && !prev.placed.has(n.key)).map((n) => n.key)) }));
  }, [graph]);
  const { placed, fresh } = layoutState;

  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const e of graph.edges) {
      m.set(e.source, (m.get(e.source) ?? new Set()).add(e.target));
      m.set(e.target, (m.get(e.target) ?? new Set()).add(e.source));
    }
    return m;
  }, [graph.edges]);

  const types = useMemo(() => [...new Set(graph.nodes.map((n) => n.type))], [graph.nodes]);
  const anchor = hover ?? selected;
  const visibleKeys = useMemo(() => {
    let keys = graph.nodes.filter((n) => n.root || !hidden.has(n.type)).map((n) => n.key);
    if (focus && selected) {
      const near = neighbours.get(selected) ?? new Set();
      keys = keys.filter((k) => k === selected || near.has(k));
    }
    return new Set(keys);
  }, [graph.nodes, hidden, focus, selected, neighbours]);

  const nodes: Node<EntityData>[] = graph.nodes
    .filter((n) => visibleKeys.has(n.key) && placed.has(n.key))
    .map((n) => {
      const pos = placed.get(n.key) ?? { x: 0, y: 0 };
      const related = !anchor || n.key === anchor || neighbours.get(anchor)?.has(n.key);
      return { id: n.key, type: "entity", position: pos, data: { node: n, dim: !related, active: n.key === selected, fresh: fresh.has(n.key) }, draggable: true, selectable: true };
    });

  const edges: Edge[] = graph.edges
    .filter((e) => visibleKeys.has(e.source) && visibleKeys.has(e.target) && placed.has(e.source) && placed.has(e.target))
    .map((e) => {
      const lit = anchor && (e.source === anchor || e.target === anchor);
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: "straight",
        label: lit ? RELATION_LABELS[e.type] ?? e.type.replace(/-/g, " ") : undefined,
        labelStyle: { fill: "var(--color-fg-2)", fontSize: 10, fontFamily: "var(--font-mono)" },
        labelBgStyle: { fill: "var(--color-ink-1)" },
        labelBgPadding: [4, 2] as [number, number],
        style: { stroke: lit ? "var(--color-fg-2)" : "var(--color-line-3)", strokeWidth: lit ? 1.4 : 1, opacity: anchor && !lit ? 0.15 : 1, transition: "opacity 200ms, stroke 200ms" },
      };
    });

  useEffect(() => {
    const t = setTimeout(() => fitView({ padding: 0.2, duration: 500, maxZoom: 1.05 }), 60);
    return () => clearTimeout(t);
  }, [placed, focus, fitView]);

  const sel = selected ? graph.nodes.find((n) => n.key === selected) : null;
  const selEdges = sel ? graph.edges.filter((e) => e.source === sel.key || e.target === sel.key) : [];
  const nodeByKey = useMemo(() => new Map(graph.nodes.map((n) => [n.key, n])), [graph.nodes]);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") {
        setSelected(null);
        setFocus(false);
      }
    },
    []
  );

  return (
    <div className="flex flex-col lg:flex-row" onKeyDown={onKeyDown}>
      <div className="relative min-w-0 flex-1 border-line-1 lg:border-r" style={{ height }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeMouseEnter={(_, n) => setHover(n.id)}
          onNodeMouseLeave={() => setHover(null)}
          onNodeClick={(_, n) => setSelected((s) => (s === n.id ? null : n.id))}
          onPaneClick={() => setSelected(null)}
          minZoom={0.2}
          maxZoom={2.2}
          nodesConnectable={false}
          colorMode="dark"
          aria-label="Evidence graph"
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="rgba(236,235,231,0.07)" />
        </ReactFlow>
        <div className="absolute top-3 left-3 flex flex-wrap gap-1">
          {types.map((t) => {
            const off = hidden.has(t);
            return (
              <button
                key={t}
                type="button"
                aria-pressed={!off}
                onClick={() => setHidden((h) => {
                  const n = new Set(h);
                  if (n.has(t)) n.delete(t);
                  else n.add(t);
                  return n;
                })}
                className={cx("mono inline-flex h-[22px] items-center gap-1.5 rounded-[2px] border bg-ink-1/90 px-1.5 text-[10px] backdrop-blur transition-opacity", off ? "border-line-1 opacity-45" : "border-line-2")}
                style={{ color: NODE_STYLE[t].color }}
                title={`${off ? "Show" : "Hide"} ${NODE_STYLE[t].label.toLowerCase()} nodes`}
              >
                {NODE_STYLE[t].glyph}
                <span className="font-sans text-fg-2">{graph.nodes.filter((n) => n.type === t).length}</span>
              </button>
            );
          })}
        </div>
        <div className="absolute right-3 bottom-3 flex flex-col gap-1">
          <button type="button" className="btn btn-sm btn-icon bg-ink-1/90" onClick={() => zoomIn({ duration: 200 })} aria-label="Zoom in">
            <Plus size={13} />
          </button>
          <button type="button" className="btn btn-sm btn-icon bg-ink-1/90" onClick={() => zoomOut({ duration: 200 })} aria-label="Zoom out">
            <Minus size={13} />
          </button>
          <button type="button" className="btn btn-sm btn-icon bg-ink-1/90" onClick={() => fitView({ padding: 0.2, duration: 400, maxZoom: 1.05 })} aria-label="Fit graph to view">
            <Maximize2 size={12} />
          </button>
          <button type="button" className={cx("btn btn-sm btn-icon bg-ink-1/90", focus && "border-fg-3 text-fg-1")} disabled={!selected} onClick={() => setFocus((f) => !f)} aria-pressed={focus} aria-label="Focus on selected node">
            <Focus size={12} />
          </button>
        </div>
        {graph.total > graph.nodes.length && <div className="absolute bottom-3 left-3 text-2xs text-fg-4">Showing {graph.nodes.length} of {graph.total} entities nearest the observable</div>}
      </div>

      <aside className="w-full shrink-0 overflow-y-auto border-t border-line-1 lg:w-[330px] lg:border-t-0" style={{ maxHeight: height }} aria-label="Entity evidence">
        {sel ? (
          <div className="animate-fade p-4">
            <div className="mb-3 flex items-start gap-2">
              <span className="mono grid h-[22px] min-w-[28px] place-items-center rounded-[2px] px-1 text-[10px] font-semibold" style={{ color: NODE_STYLE[sel.type].color, background: `color-mix(in srgb, ${NODE_STYLE[sel.type].color} 14%, transparent)` }}>
                {NODE_STYLE[sel.type].glyph}
              </span>
              <div className="min-w-0 flex-1">
                <div className="label">{NODE_STYLE[sel.type].label}</div>
                <div className="mono text-[12.5px] break-all text-fg-1">{sel.value}</div>
                {sel.label && <div className="text-xs text-fg-3">{sel.label}</div>}
              </div>
              <button type="button" className="btn btn-ghost btn-sm btn-icon" onClick={() => setSelected(null)} aria-label="Clear selection">
                <X size={13} />
              </button>
            </div>
            <div className="mb-4 flex flex-wrap gap-1.5">
              <CopyButton value={sel.value} size="md" className="!w-auto px-2" />
              {PIVOTABLE[sel.type] && !sel.root && (
                <button type="button" className="btn btn-sm" onClick={() => void start(sel.value, "QUICK")}>
                  <Radar size={12} /> Investigate
                </button>
              )}
              {(sel.type === "technique" || sel.type === "software" || sel.type === "group") && (
                <a className="btn btn-sm" href={`/attack/${sel.value}`}>
                  <Crosshair size={12} /> ATT&CK entry
                </a>
              )}
            </div>
            <div className="label mb-2">Evidence · {selEdges.length} relationship{selEdges.length === 1 ? "" : "s"}</div>
            <ul className="flex flex-col gap-2">
              {selEdges.map((e) => {
                const other = nodeByKey.get(e.source === sel.key ? e.target : e.source)!;
                const outgoing = e.source === sel.key;
                return (
                  <li key={e.id} className="rounded-[2px] border border-line-1 bg-ink-0 p-2.5">
                    <div className="flex items-center gap-1.5 text-xs">
                      <span className="text-fg-3">{outgoing ? "" : "← "}{RELATION_LABELS[e.type] ?? e.type.replace(/-/g, " ")}{outgoing ? " →" : ""}</span>
                      <button type="button" className="mono min-w-0 truncate text-left text-[11.5px] text-fg-1 hover:underline" onClick={() => setSelected(other.key)}>
                        {other.label && other.type !== "domain" ? other.label : other.value}
                      </button>
                    </div>
                    <ul className="mt-1.5 flex flex-col gap-1">
                      {e.evidence.map((ev, i) => (
                        <li key={i} className="text-[11.5px] text-fg-2">
                          {ev}
                        </li>
                      ))}
                    </ul>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      {e.providers.map((p) => (
                        <Prov key={p} id={p} />
                      ))}
                      <span className="sr-only">Reported by {e.providers.map(name).join(", ")}</span>
                      <span className="mono text-[10.5px] text-fg-4">
                        observed <Time iso={e.observedAt} />
                      </span>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : (
          <div className="p-4 text-sm text-fg-3">
            <div className="label mb-2">Evidence graph</div>
            <p className="mb-3">Every edge is a relationship reported by a source, with its evidence. Nothing is inferred for decoration.</p>
            <ul className="flex flex-col gap-1.5 text-xs">
              <li>Hover an entity to trace its neighbourhood.</li>
              <li>Select it to read the evidence and pivot into a new investigation.</li>
              <li>Focus mode isolates the selection; chips at top-left filter entity types.</li>
            </ul>
            <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
              <div>
                <div className="display tabular text-xl text-fg-1">{graph.nodes.length}</div>
                <div className="text-fg-4">entities</div>
              </div>
              <div>
                <div className="display tabular text-xl text-fg-1">{graph.edges.length}</div>
                <div className="text-fg-4">relationships</div>
              </div>
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}

export default function EvidenceGraph({ inv, height = 560 }: { inv: InvestigationRecord; height?: number }) {
  return (
    <ReactFlowProvider>
      <GraphCanvas inv={inv} height={height} />
    </ReactFlowProvider>
  );
}
