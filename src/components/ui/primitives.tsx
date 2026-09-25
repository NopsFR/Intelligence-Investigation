"use client";

import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { cx } from "@/lib/client/cx";

export function Panel({
  title,
  meta,
  actions,
  children,
  className,
  bodyClassName,
  ticks = true,
  id,
}: {
  title?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  ticks?: boolean;
  id?: string;
}) {
  return (
    <section id={id} className={cx("panel", ticks && "panel-ticks", className)} aria-label={typeof title === "string" ? title : undefined}>
      {(title || actions) && (
        <header className="flex min-h-[40px] items-center gap-3 border-b border-line-1 px-[var(--panel-pad)] py-2">
          {title && <h2 className="label text-fg-2">{title}</h2>}
          {meta && <div className="min-w-0 truncate text-xs text-fg-3">{meta}</div>}
          {actions && <div className="ml-auto flex items-center gap-1.5">{actions}</div>}
        </header>
      )}
      <div className={cx("p-[var(--panel-pad)]", bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: ReactNode; title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-end gap-x-6 gap-y-3">
      <div className="min-w-0 flex-1">
        {eyebrow && <div className="label mb-1.5 flex items-center gap-2">{eyebrow}</div>}
        <h1 className="display text-2xl text-fg-1">{title}</h1>
        {description && <p className="mt-1.5 max-w-3xl text-sm text-fg-3">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function EmptyState({ icon, title, children, action, className }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cx("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      {icon && (
        <div className="mb-4 grid h-10 w-10 place-items-center rounded-[3px] border border-line-2 bg-ink-2 text-fg-3" aria-hidden>
          {icon}
        </div>
      )}
      <div className="text-sm font-semibold text-fg-1">{title}</div>
      {children && <div className="mt-1.5 max-w-md text-sm text-fg-3">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorNote({ title = "Something went wrong", children, action }: { title?: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-[3px] border px-3 py-2.5 text-sm" style={{ borderColor: "color-mix(in srgb, var(--color-err) 35%, transparent)", background: "color-mix(in srgb, var(--color-err) 7%, transparent)" }}>
      <span aria-hidden className="mt-[6px] h-[7px] w-[7px] shrink-0 rotate-45 bg-err" />
      <div className="min-w-0 flex-1">
        <div className="font-semibold text-fg-1">{title}</div>
        {children && <div className="mt-0.5 text-fg-2">{children}</div>}
      </div>
      {action}
    </div>
  );
}

export function Skeleton({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return <div aria-hidden className={cx("skeleton", className)} style={style} />;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}

export function CopyButton({ value, label = "Copy", className, size = "sm" }: { value: string; label?: string; className?: string; size?: "sm" | "md" }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  return (
    <button
      type="button"
      className={cx("btn btn-ghost btn-icon", size === "sm" && "btn-sm", className)}
      aria-label={copied ? "Copied" : `${label}: ${value.slice(0, 60)}`}
      title={copied ? "Copied" : label}
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          clearTimeout(timer.current);
          timer.current = setTimeout(() => setCopied(false), 1400);
        } catch {
          /* clipboard blocked */
        }
      }}
    >
      {copied ? <Check size={13} className="text-ok" /> : <Copy size={13} />}
    </button>
  );
}

/** A labelled value in a definition grid. */
export function Stat({ label, value, sub, className }: { label: ReactNode; value: ReactNode; sub?: ReactNode; className?: string }) {
  return (
    <div className={cx("min-w-0", className)}>
      <div className="label mb-1">{label}</div>
      <div className="display tabular text-xl text-fg-1">{value}</div>
      {sub && <div className="mt-0.5 truncate text-xs text-fg-3">{sub}</div>}
    </div>
  );
}

/** Minimal inline bar sparkline for real series (never decorative). */
export function Bars({ values, labels, height = 36, color = "var(--color-fg-3)", highlightLast = true, className }: { values: number[]; labels?: string[]; height?: number; color?: string; highlightLast?: boolean; className?: string }) {
  const max = Math.max(1, ...values);
  return (
    <div className={cx("flex items-end gap-[3px]", className)} style={{ height }} role="img" aria-label={labels ? values.map((v, i) => `${labels[i]}: ${v}`).join(", ") : values.join(", ")}>
      {values.map((v, i) => (
        <div key={i} className="group relative flex-1" style={{ height: "100%" }}>
          <div
            className="absolute bottom-0 w-full rounded-[1px] transition-[height] duration-500"
            style={{ height: v ? `${Math.max(8, (v / max) * 100)}%` : "2px", background: v ? (highlightLast && i === values.length - 1 ? "var(--color-fg-1)" : color) : "var(--color-line-2)" }}
          />
          {labels && (
            <div className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-1 hidden -translate-x-1/2 whitespace-nowrap rounded-[2px] border border-line-2 bg-ink-3 px-1.5 py-0.5 text-2xs text-fg-1 group-hover:block">
              {labels[i]} · {v}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export function Segmented<T extends string>({ value, options, onChange, label, size = "md" }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; label: string; size?: "sm" | "md" }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-[3px] border border-line-2 bg-ink-0 p-[2px]">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cx(
            "rounded-[2px] px-2.5 font-medium transition-colors",
            size === "sm" ? "h-[22px] text-xs" : "h-[26px] text-sm",
            value === o.value ? "bg-ink-3 text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-3)]" : "text-fg-3 hover:text-fg-1"
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label, description }: { checked: boolean; onChange: (v: boolean) => void; label: string; description?: string }) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-4">
      <span>
        <span className="block text-sm text-fg-1">{label}</span>
        {description && <span className="mt-0.5 block text-xs text-fg-3">{description}</span>}
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={cx("relative mt-0.5 h-[18px] w-[32px] shrink-0 rounded-full border transition-colors", checked ? "border-fg-3 bg-fg-2" : "border-line-3 bg-ink-3")}
      >
        <span className={cx("absolute top-[2px] h-[12px] w-[12px] rounded-full transition-[left,background] duration-200", checked ? "left-[16px] bg-ink-0" : "left-[2px] bg-fg-3")} />
      </button>
    </label>
  );
}
