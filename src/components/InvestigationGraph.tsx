"use client";

import { useMemo, useState } from "react";
import ReactFlow, { Background, Controls, type Edge, type Node } from "reactflow";
import "reactflow/dist/style.css";
import type { RelationshipRecord } from "@/types/investigation";

export function InvestigationGraph({
  root,
  relationships,
}: {
  root: string;
  relationships: RelationshipRecord[];
}) {
  const [selected, setSelected] = useState<RelationshipRecord | null>(null);

  const { nodes, edges } = useMemo(() => buildGraph(root, relationships), [root, relationships]);

  if (relationships.length === 0) {
    return (
      <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] px-4 py-8 text-center font-mono text-sm text-[var(--nops-text-faint)]">
        No evidence-backed relationships were discovered for this observable.
      </div>
    );
  }

  return (
    <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)]">
      <div style={{ height: 420 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          proOptions={{ hideAttribution: true }}
          onEdgeClick={(_e, edge) => {
            const rel = relationships.find((r) => r.id === edge.id);
            setSelected(rel ?? null);
          }}
          onNodeClick={() => setSelected(null)}
        >
          <Background color="#262629" gap={20} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="border-t border-[var(--nops-border)] px-4 py-3 font-mono text-xs">
        {selected ? (
          <div className="space-y-1">
            <p className="text-[var(--nops-text)]">
              {selected.sourceNode} <span className="text-[var(--nops-text-faint)]">→ {selected.relationType} →</span>{" "}
              {selected.targetNode}
            </p>
            <p className="text-[var(--nops-text-dim)]">{selected.evidence}</p>
            <p className="text-[var(--nops-text-faint)]">Source: {selected.sourceProvider}</p>
          </div>
        ) : (
          <p className="text-[var(--nops-text-faint)]">Click an edge to inspect its evidence and source.</p>
        )}
      </div>
    </div>
  );
}

function buildGraph(root: string, relationships: RelationshipRecord[]): { nodes: Node[]; edges: Edge[] } {
  const nodeIds = new Set<string>([root]);
  for (const r of relationships) {
    nodeIds.add(r.sourceNode);
    nodeIds.add(r.targetNode);
  }

  const idList = Array.from(nodeIds);
  const radius = 220;

  const nodes: Node[] = idList.map((id, i) => {
    const isRoot = id === root;
    const angle = (2 * Math.PI * i) / Math.max(idList.length - 1, 1);
    const position = isRoot
      ? { x: 400, y: 200 }
      : { x: 400 + radius * Math.cos(angle), y: 200 + radius * Math.sin(angle) };

    return {
      id,
      position,
      data: { label: id },
      style: {
        background: isRoot ? "var(--nops-red-bg)" : "#16161a",
        border: `1px solid ${isRoot ? "#7c1a28" : "#35353a"}`,
        color: "#e7e7e5",
        fontFamily: "var(--font-mono-tech)",
        fontSize: 11,
        borderRadius: 4,
        padding: 8,
        width: 180,
      },
    };
  });

  const edges: Edge[] = relationships.map((r) => ({
    id: r.id,
    source: r.sourceNode,
    target: r.targetNode,
    label: r.relationType.replace(/_/g, " "),
    labelStyle: { fill: "#98989c", fontSize: 9, fontFamily: "var(--font-mono-tech)" },
    style: { stroke: "#35353a" },
    animated: false,
  }));

  return { nodes, edges };
}
