"use client";

import { FileUp, Lock } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { cx } from "@/lib/client/cx";

// ───────────────────────────── local file intake

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

/**
 * Drop zone that reads files in the browser. Nothing is uploaded: the caller
 * receives the bytes and analyses them locally.
 */
export function FileDrop({
  onFile,
  accept,
  maxBytes,
  title,
  description,
  busy = false,
  compact = false,
}: {
  onFile: (file: File, bytes: Uint8Array) => void;
  accept?: string;
  maxBytes: number;
  title: string;
  description?: ReactNode;
  busy?: boolean;
  compact?: boolean;
}) {
  const [over, setOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const take = useCallback(
    async (file: File | undefined) => {
      if (!file) return;
      setError(null);
      if (file.size > maxBytes) {
        setError(`${file.name} is ${formatBytes(file.size)}; the limit for in-browser analysis is ${formatBytes(maxBytes)}.`);
        return;
      }
      if (file.size === 0) {
        setError(`${file.name} is empty.`);
        return;
      }
      onFile(file, new Uint8Array(await file.arrayBuffer()));
    },
    [maxBytes, onFile]
  );

  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        aria-label={`${title}. Choose a file or drop it here.`}
        onClick={() => input.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), input.current?.click())}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          void take(e.dataTransfer.files[0]);
        }}
        className={cx(
          "group relative flex cursor-pointer flex-col items-center justify-center rounded-[3px] border border-dashed text-center transition-[border-color,background-color] duration-200",
          compact ? "px-4 py-5" : "grid-canvas px-6 py-12",
          over ? "border-ice bg-[color-mix(in_srgb,var(--color-ice)_6%,transparent)]" : "border-line-3 hover:border-fg-4 hover:bg-ink-2/40"
        )}
      >
        <div className={cx("mb-3 grid h-10 w-10 place-items-center rounded-[3px] border border-line-2 bg-ink-1 text-fg-2 transition-transform duration-200", over && "scale-110", busy && "animate-pulse")} aria-hidden>
          <FileUp size={17} />
        </div>
        <div className="text-sm font-semibold text-fg-1">{busy ? "Analysing…" : title}</div>
        {description && <div className="mt-1 max-w-lg text-xs text-fg-3">{description}</div>}
        <div className="mt-3 inline-flex items-center gap-1.5 text-[11px] text-fg-4">
          <Lock size={11} /> Processed in your browser — the file is never uploaded · limit {formatBytes(maxBytes)}
        </div>
        <input
          ref={input}
          type="file"
          accept={accept}
          className="sr-only"
          tabIndex={-1}
          onChange={(e) => {
            void take(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
      </div>
      {error && (
        <p role="alert" className="mt-2 text-xs text-err">
          {error}
        </p>
      )}
    </div>
  );
}

// ───────────────────────────── virtual list

/** Fixed-row-height windowing for long lists (packets, strings, symbols). */
export function useVirtual(count: number, rowHeight: number, overscan = 8) {
  const ref = useRef<HTMLDivElement>(null);
  const [range, setRange] = useState({ start: 0, end: 40 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => {
      const start = Math.max(0, Math.floor(el.scrollTop / rowHeight) - overscan);
      const end = Math.min(count, Math.ceil((el.scrollTop + el.clientHeight) / rowHeight) + overscan);
      setRange((r) => (r.start === start && r.end === end ? r : { start, end }));
    };
    update();
    el.addEventListener("scroll", update, { passive: true });
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => {
      el.removeEventListener("scroll", update);
      ro.disconnect();
    };
  }, [count, rowHeight, overscan]);
  const scrollTo = useCallback((index: number) => {
    const el = ref.current;
    if (!el) return;
    const top = index * rowHeight;
    if (top < el.scrollTop || top > el.scrollTop + el.clientHeight - rowHeight) el.scrollTop = Math.max(0, top - el.clientHeight / 3);
  }, [rowHeight]);
  return { ref, start: range.start, end: range.end, total: count * rowHeight, scrollTo };
}

// ───────────────────────────── hex viewer

export interface HexHighlight {
  start: number;
  end: number;
  label: string;
  color?: string;
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
const printable = (b: number) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·");

/** Virtualised hex dump with labelled highlight ranges and offset navigation. */
export function HexView({ bytes, highlights = [], height = 420, focus }: { bytes: Uint8Array; highlights?: HexHighlight[]; height?: number; focus?: number }) {
  const rows = Math.ceil(bytes.length / 16);
  const rowHeight = 20;
  const { ref: scrollRef, start, end, total, scrollTo } = useVirtual(rows, rowHeight, 12);
  const [jump, setJump] = useState("");
  const [hover, setHover] = useState<number | null>(null);

  useEffect(() => {
    if (focus !== undefined) scrollTo(Math.floor(focus / 16));
  }, [focus, scrollTo]);

  const colorAt = useMemo(() => {
    const sorted = [...highlights].sort((a, b) => a.start - b.start);
    return (offset: number) => sorted.find((h) => offset >= h.start && offset < h.end);
  }, [highlights]);

  const hovered = hover !== null ? colorAt(hover) : undefined;
  const width = Math.max(8, bytes.length.toString(16).length);

  return (
    <div className="rounded-[2px] border border-line-1 bg-ink-0">
      <div className="flex flex-wrap items-center gap-3 border-b border-line-1 px-3 py-1.5 text-[11px] text-fg-3">
        <form
          className="flex items-center gap-1.5"
          onSubmit={(e) => {
            e.preventDefault();
            const n = jump.trim().toLowerCase().startsWith("0x") ? parseInt(jump, 16) : Number(jump);
            if (Number.isFinite(n) && n >= 0 && n < bytes.length) scrollTo(Math.floor(n / 16));
          }}
        >
          <label htmlFor="hex-jump">Go to offset</label>
          <input id="hex-jump" className="input mono h-[22px] w-[110px] px-1.5 text-[11px]" placeholder="0x400" value={jump} onChange={(e) => setJump(e.target.value)} />
        </form>
        <span className="mono">{bytes.length.toLocaleString("en-GB")} bytes</span>
        <span className="mono ml-auto min-h-[14px] text-fg-2">
          {hover !== null && (
            <>
              0x{hover.toString(16).padStart(width, "0")} = 0x{HEX[bytes[hover]]} ({bytes[hover]}){hovered && <span className="ml-2 text-fg-1">· {hovered.label}</span>}
            </>
          )}
        </span>
      </div>
      <div ref={scrollRef} className="relative overflow-auto" style={{ height }} onMouseLeave={() => setHover(null)}>
        <div style={{ height: total, position: "relative" }}>
          {Array.from({ length: end - start }, (_, k) => {
            const row = start + k;
            const base = row * 16;
            const slice = bytes.subarray(base, Math.min(base + 16, bytes.length));
            return (
              <div key={row} className="mono absolute right-0 left-0 flex items-center gap-4 px-3 text-[11.5px] leading-none whitespace-pre" style={{ top: row * rowHeight, height: rowHeight }}>
                <span className="w-[76px] shrink-0 text-fg-4 tabular">{base.toString(16).padStart(width, "0")}</span>
                <span className="flex gap-[5px]">
                  {Array.from({ length: 16 }, (_, i) => {
                    const off = base + i;
                    if (i >= slice.length) return <span key={i} className="w-[15px]" />;
                    const h = colorAt(off);
                    return (
                      <span
                        key={i}
                        onMouseEnter={() => setHover(off)}
                        className={cx("w-[15px] text-center", i === 8 && "ml-2", hover === off ? "rounded-[1px] bg-fg-1 text-ink-0" : slice[i] === 0 ? "text-fg-4" : "text-fg-2")}
                        style={h && hover !== off ? { color: h.color ?? "var(--color-ice)", background: `color-mix(in srgb, ${h.color ?? "var(--color-ice)"} 12%, transparent)` } : undefined}
                      >
                        {HEX[slice[i]]}
                      </span>
                    );
                  })}
                </span>
                <span className="text-fg-3">{Array.from(slice, printable).join("")}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ───────────────────────────── code editor with highlighting

export interface Token {
  text: string;
  kind?: "keyword" | "string" | "comment" | "number" | "operator" | "identifier" | "meta" | "hex" | "regex" | "key" | "tag";
}

const TOKEN_COLOR: Record<NonNullable<Token["kind"]>, string> = {
  keyword: "var(--color-sev-low)",
  string: "#b9c98a",
  comment: "var(--color-fg-4)",
  number: "var(--color-sev-medium)",
  operator: "var(--color-fg-2)",
  identifier: "var(--color-fg-1)",
  meta: "var(--color-ice)",
  hex: "var(--color-sev-high)",
  regex: "#c9a0d8",
  key: "var(--color-ice)",
  tag: "var(--color-sev-medium)",
};

/**
 * Textarea with a synchronised, tokenised overlay. Keeps native editing,
 * selection, undo and accessibility; highlighting is purely visual.
 */
export function CodeEditor({
  value,
  onChange,
  tokenize,
  label,
  minHeight = 280,
  errors = [],
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  tokenize: (line: string) => Token[];
  label: string;
  minHeight?: number;
  errors?: { line: number; message: string }[];
  placeholder?: string;
}) {
  const pre = useRef<HTMLPreElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  const lines = value.split("\n");
  const errorLines = new Map(errors.map((e) => [e.line, e.message]));
  const sync = (e: React.UIEvent<HTMLTextAreaElement>) => {
    if (pre.current) {
      pre.current.scrollTop = e.currentTarget.scrollTop;
      pre.current.scrollLeft = e.currentTarget.scrollLeft;
    }
    if (gutter.current) gutter.current.scrollTop = e.currentTarget.scrollTop;
  };
  const shared = "mono m-0 whitespace-pre p-3 text-[12px] leading-[19px]";
  return (
    <div className="relative flex overflow-hidden rounded-[2px] border border-line-2 bg-ink-0 focus-within:border-[color-mix(in_srgb,var(--color-ice)_50%,var(--color-line-3))]" style={{ height: minHeight }}>
      <div ref={gutter} aria-hidden className="mono w-[42px] shrink-0 overflow-hidden border-r border-line-1 py-3 text-right text-[11px] leading-[19px] text-fg-4 select-none">
        {lines.map((_, i) => (
          <div key={i} className={cx("pr-2", errorLines.has(i + 1) && "bg-[color-mix(in_srgb,var(--color-err)_18%,transparent)] text-err")} title={errorLines.get(i + 1)}>
            {i + 1}
          </div>
        ))}
      </div>
      <div className="relative min-w-0 flex-1">
        <pre ref={pre} aria-hidden className={cx(shared, "pointer-events-none absolute inset-0 overflow-hidden")}>
          {lines.map((line, i) => (
            <div key={i} className={cx("min-h-[19px]", errorLines.has(i + 1) && "underline decoration-err decoration-wavy underline-offset-4")}>
              {tokenize(line).map((t, j) => (
                <span key={j} style={t.kind ? { color: TOKEN_COLOR[t.kind] } : undefined}>
                  {t.text}
                </span>
              ))}
            </div>
          ))}
        </pre>
        <textarea
          aria-label={label}
          value={value}
          placeholder={placeholder}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          wrap="off"
          onChange={(e) => onChange(e.target.value)}
          onScroll={sync}
          onKeyDown={(e) => {
            if (e.key === "Tab" && !e.shiftKey) {
              e.preventDefault();
              const t = e.currentTarget;
              const { selectionStart: a, selectionEnd: b } = t;
              const next = `${value.slice(0, a)}  ${value.slice(b)}`;
              onChange(next);
              requestAnimationFrame(() => t.setSelectionRange(a + 2, a + 2));
            }
          }}
          className={cx(shared, "absolute inset-0 h-full w-full resize-none overflow-auto bg-transparent text-transparent caret-fg-1 outline-none placeholder:text-fg-4 selection:bg-[color-mix(in_srgb,var(--color-ice)_30%,transparent)]")}
        />
      </div>
    </div>
  );
}

/** Two-level key/value tree used by dissectors (packet layers, headers). */
export function Tree({ nodes }: { nodes: TreeNode[] }) {
  return (
    <ul className="mono text-[11.5px]">
      {nodes.map((n, i) => (
        <TreeItem key={i} node={n} depth={0} />
      ))}
    </ul>
  );
}

export interface TreeNode {
  label: string;
  value?: string;
  children?: TreeNode[];
  onSelect?: () => void;
}

function TreeItem({ node, depth }: { node: TreeNode; depth: number }) {
  const [open, setOpen] = useState(depth === 0);
  const has = Boolean(node.children?.length);
  return (
    <li>
      <button
        type="button"
        onClick={() => (has ? setOpen((o) => !o) : node.onSelect?.())}
        onFocus={node.onSelect}
        aria-expanded={has ? open : undefined}
        className="flex w-full items-baseline gap-1.5 rounded-[2px] py-[3px] pr-2 text-left hover:bg-ink-2"
        style={{ paddingLeft: 8 + depth * 14 }}
      >
        <span className={cx("w-[10px] shrink-0 text-fg-4 transition-transform", has ? "" : "opacity-0", open && "rotate-90")} aria-hidden>
          ›
        </span>
        <span className={depth === 0 ? "font-semibold text-fg-1" : "text-fg-3"}>{node.label}</span>
        {node.value !== undefined && <span className="min-w-0 break-all text-fg-1">{node.value}</span>}
      </button>
      {has && open && (
        <ul>
          {node.children!.map((c, i) => (
            <TreeItem key={i} node={c} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}
