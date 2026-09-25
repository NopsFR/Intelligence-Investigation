"use client";

import { X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { cx } from "@/lib/client/cx";

// ───────────────────────────── focus helpers

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

function useFocusTrap(open: boolean, ref: React.RefObject<HTMLElement | null>, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const first = node?.querySelector<HTMLElement>("[data-autofocus]") ?? node?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? node)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      } else if (e.key === "Tab" && node) {
        const items = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null);
        if (!items.length) return;
        const [a, b] = [items[0], items[items.length - 1]];
        if (e.shiftKey && document.activeElement === a) {
          e.preventDefault();
          b.focus();
        } else if (!e.shiftKey && document.activeElement === b) {
          e.preventDefault();
          a.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.body.style.overflow = overflow;
      previous?.focus?.();
    };
  }, [open, ref, onClose]);
}

function usePresence(open: boolean, ms = 220) {
  const [mounted, setMounted] = useState(open);
  const [visible, setVisible] = useState(open);
  useEffect(() => {
    if (open) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- mount before animating in
      setMounted(true);
      const r = requestAnimationFrame(() => requestAnimationFrame(() => setVisible(true)));
      return () => cancelAnimationFrame(r);
    }
    setVisible(false);
    const t = setTimeout(() => setMounted(false), ms);
    return () => clearTimeout(t);
  }, [open, ms]);
  return { mounted, visible };
}

// ───────────────────────────── Drawer

export function Drawer({ open, onClose, title, subtitle, children, width = 560, footer }: { open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode; width?: number; footer?: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const { mounted, visible } = usePresence(open);
  const titleId = useId();
  useFocusTrap(open, ref, onClose);
  if (!mounted) return null;
  return createPortal(
    <div className="fixed inset-0 z-50">
      <div className={cx("absolute inset-0 bg-black/55 transition-opacity duration-200", visible ? "opacity-100" : "opacity-0")} onClick={onClose} aria-hidden />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cx(
          "absolute top-0 right-0 flex h-full max-w-full flex-col border-l border-line-2 bg-ink-1 shadow-[-24px_0_60px_rgba(0,0,0,0.45)] transition-transform duration-[260ms] ease-[var(--ease-out-quint)]",
          visible ? "translate-x-0" : "translate-x-[104%]"
        )}
        style={{ width }}
      >
        <header className="flex items-start gap-3 border-b border-line-1 px-5 py-3.5">
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="truncate text-base font-semibold text-fg-1">
              {title}
            </h2>
            {subtitle && <div className="mt-0.5 text-xs text-fg-3">{subtitle}</div>}
          </div>
          <button type="button" className="btn btn-ghost btn-icon btn-sm -mr-1" onClick={onClose} aria-label="Close panel">
            <X size={15} />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
        {footer && <footer className="border-t border-line-1 px-5 py-3">{footer}</footer>}
      </div>
    </div>,
    document.body
  );
}

// ───────────────────────────── Dialog

export function Dialog({ open, onClose, title, children, footer, width = 440 }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; width?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const { mounted, visible } = usePresence(open, 160);
  const titleId = useId();
  useFocusTrap(open, ref, onClose);
  if (!mounted) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 grid place-items-center p-4">
      <div className={cx("absolute inset-0 bg-black/60 transition-opacity duration-150", visible ? "opacity-100" : "opacity-0")} onClick={onClose} aria-hidden />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cx("panel panel-ticks relative w-full shadow-[0_24px_80px_rgba(0,0,0,0.6)] transition-[opacity,transform] duration-150", visible ? "scale-100 opacity-100" : "scale-[0.98] opacity-0")}
        style={{ maxWidth: width }}
      >
        <header className="border-b border-line-1 px-5 py-3.5">
          <h2 id={titleId} className="text-base font-semibold text-fg-1">
            {title}
          </h2>
        </header>
        <div className="px-5 py-4 text-sm text-fg-2">{children}</div>
        {footer && <footer className="flex justify-end gap-2 border-t border-line-1 px-5 py-3">{footer}</footer>}
      </div>
    </div>,
    document.body
  );
}

// ───────────────────────────── Tabs (animated indicator, roving focus)

export interface TabItem {
  id: string;
  label: ReactNode;
  count?: number;
  disabled?: boolean;
  hint?: string;
}

export function Tabs({ items, value, onChange, label, className }: { items: TabItem[]; value: string; onChange: (id: string) => void; label: string; className?: string }) {
  const listRef = useRef<HTMLDivElement>(null);
  const [indicator, setIndicator] = useState<{ left: number; width: number } | null>(null);

  useLayoutEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-tab="${CSS.escape(value)}"]`);
    if (el) setIndicator({ left: el.offsetLeft, width: el.offsetWidth });
    el?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [value, items]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    const enabled = items.filter((i) => !i.disabled);
    const idx = enabled.findIndex((i) => i.id === value);
    let next: TabItem | undefined;
    if (e.key === "ArrowRight") next = enabled[(idx + 1) % enabled.length];
    else if (e.key === "ArrowLeft") next = enabled[(idx - 1 + enabled.length) % enabled.length];
    else if (e.key === "Home") next = enabled[0];
    else if (e.key === "End") next = enabled[enabled.length - 1];
    if (next) {
      e.preventDefault();
      onChange(next.id);
      listRef.current?.querySelector<HTMLElement>(`[data-tab="${CSS.escape(next.id)}"]`)?.focus();
    }
  };

  return (
    <div className={cx("relative border-b border-line-1", className)}>
      <div ref={listRef} role="tablist" aria-label={label} onKeyDown={onKeyDown} className="scrollbar-none relative flex overflow-x-auto" style={{ scrollbarWidth: "none" }}>
        {items.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            data-tab={t.id}
            id={`tab-${t.id}`}
            aria-selected={t.id === value}
            aria-controls={`panel-${t.id}`}
            tabIndex={t.id === value ? 0 : -1}
            disabled={t.disabled}
            title={t.hint}
            onClick={() => onChange(t.id)}
            className={cx(
              "relative flex h-[38px] shrink-0 items-center gap-1.5 px-3 text-sm font-medium transition-colors disabled:opacity-35",
              t.id === value ? "text-fg-1" : "text-fg-3 hover:text-fg-1"
            )}
          >
            {t.label}
            {t.count !== undefined && <span className={cx("mono tabular text-[10.5px]", t.id === value ? "text-fg-2" : "text-fg-4")}>{t.count}</span>}
          </button>
        ))}
        {indicator && <span aria-hidden className="absolute bottom-0 h-[2px] bg-signal transition-[left,width] duration-300 ease-[var(--ease-out-quint)]" style={{ left: indicator.left, width: indicator.width }} />}
      </div>
    </div>
  );
}

// ───────────────────────────── Toasts

type ToastKind = "info" | "success" | "error";
interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  body?: string;
}

const ToastCtx = createContext<(t: Omit<Toast, "id">) => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);
  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = ++counter.current;
    setToasts((prev) => [...prev.slice(-3), { ...t, id }]);
    setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), t.kind === "error" ? 7000 : 4000);
  }, []);
  const value = useMemo(() => push, [push]);
  return (
    <ToastCtx.Provider value={value}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed right-4 bottom-[calc(var(--statusbar-h)+12px)] z-[60] flex w-[340px] max-w-[calc(100vw-32px)] flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} role={t.kind === "error" ? "alert" : "status"} className="panel pointer-events-auto flex animate-rise gap-3 px-3.5 py-3 shadow-[0_12px_40px_rgba(0,0,0,0.5)]">
            <span aria-hidden className="mt-[6px] h-[7px] w-[7px] shrink-0 rotate-45" style={{ background: t.kind === "error" ? "var(--color-err)" : t.kind === "success" ? "var(--color-ok)" : "var(--color-ice)" }} />
            <div className="min-w-0">
              <div className="text-sm font-semibold text-fg-1">{t.title}</div>
              {t.body && <div className="mt-0.5 text-xs text-fg-3">{t.body}</div>}
            </div>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  return useContext(ToastCtx);
}

// ───────────────────────────── Tooltip (hover + focus, no JS positioning)

export function Tip({ content, children, side = "top" }: { content: ReactNode; children: ReactNode; side?: "top" | "bottom" }) {
  return (
    <span className="group/tip relative inline-flex">
      {children}
      <span
        role="tooltip"
        className={cx(
          "pointer-events-none absolute left-1/2 z-40 w-max max-w-[280px] -translate-x-1/2 rounded-[3px] border border-line-2 bg-ink-3 px-2 py-1 text-xs text-fg-1 opacity-0 shadow-[0_8px_24px_rgba(0,0,0,0.5)] transition-opacity delay-0 duration-100 group-focus-within/tip:opacity-100 group-hover/tip:opacity-100 group-hover/tip:delay-300",
          side === "top" ? "bottom-[calc(100%+6px)]" : "top-[calc(100%+6px)]"
        )}
      >
        {content}
      </span>
    </span>
  );
}
