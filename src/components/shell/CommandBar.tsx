"use client";

import { ChevronDown, CornerDownLeft, Loader2, Lock, Radar, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { OBSERVABLE_SHORT } from "@/lib/core/types";
import { cx } from "@/lib/client/cx";
import { useDetection } from "@/lib/client/detect";
import { useInvestigate } from "@/lib/client/investigate";
import { useSession } from "@/lib/client/session";
import { Kbd } from "@/components/ui/primitives";

export function CommandBar({ onOpenPalette }: { onOpenPalette: () => void }) {
  const [value, setValue] = useState("");
  const [menu, setMenu] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const { detection, pending: detecting } = useDetection(value);
  const { start, pending } = useInvestigate();
  const { session } = useSession();
  const canDeep = session?.operator ?? false;
  const invalid = Boolean(value.trim() && detection && detection.type === null && !detecting);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      const typing = target.closest("input, textarea, select, [contenteditable=true]");
      if (e.key === "/" && !typing) {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!menu) return;
    const close = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) setMenu(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [menu]);

  const submit = async (mode: "QUICK" | "DEEP") => {
    setMenu(false);
    if (!value.trim() || invalid) return;
    const res = await start(value, mode);
    if (res) setValue("");
  };

  return (
    <form
      role="search"
      className="flex min-w-0 flex-1 items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        void submit("QUICK");
      }}
    >
      <div
        className={cx(
          "group relative flex h-[34px] min-w-0 flex-1 items-center rounded-[3px] border bg-ink-0 transition-[border-color,box-shadow] duration-150",
          invalid ? "border-[color-mix(in_srgb,var(--color-err)_50%,transparent)]" : "border-line-2 hover:border-line-3 focus-within:border-[color-mix(in_srgb,var(--color-ice)_50%,var(--color-line-3))] focus-within:shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-ice)_10%,transparent)]"
        )}
      >
        <Search size={14} className="ml-3 shrink-0 text-fg-4" aria-hidden />
        <span className="ml-2 flex h-[18px] min-w-[46px] shrink-0 items-center" aria-live="polite">
          {detecting ? (
            <Loader2 size={12} className="animate-spin text-fg-4" aria-label="Detecting type" />
          ) : detection?.type ? (
            <span className="mono inline-flex h-[18px] animate-fade items-center rounded-[2px] bg-ink-3 px-1.5 text-[10px] font-medium tracking-wide text-fg-1 uppercase shadow-[inset_0_0_0_1px_var(--color-line-3)]" title={detection.label}>
              {OBSERVABLE_SHORT[detection.type]}
            </span>
          ) : invalid ? (
            <span className="text-2xs font-medium text-err">Unknown</span>
          ) : null}
        </span>
        <input
          ref={inputRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.shiftKey || e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              void submit("DEEP");
            } else if (e.key === "Escape") {
              setValue("");
              inputRef.current?.blur();
            }
          }}
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          aria-label="Observable to investigate"
          aria-invalid={invalid}
          placeholder="Investigate an IP, domain, URL, hash, CVE, ASN, email or certificate…"
          className="mono h-full min-w-0 flex-1 bg-transparent px-2 text-[12.5px] text-fg-1 outline-none placeholder:font-sans placeholder:text-sm placeholder:text-fg-4"
        />
        {detection?.normalized && detection.normalized !== value.trim() && !detecting && (
          <span className="mono hidden max-w-[220px] truncate pr-2 text-[11px] text-fg-4 xl:block" title="Normalised form">
            → {detection.normalized}
          </span>
        )}
        <button type="button" onClick={onOpenPalette} className="mr-1.5 hidden shrink-0 items-center gap-1 rounded-[2px] px-1 text-fg-4 hover:text-fg-2 md:flex" aria-label="Open command palette">
          <Kbd>⌘</Kbd>
          <Kbd>K</Kbd>
        </button>
      </div>

      <div ref={menuRef} className="relative flex shrink-0">
        <button type="submit" className="btn btn-primary rounded-r-none pr-3 pl-3" disabled={pending || !value.trim() || invalid} aria-label="Run quick scan">
          {pending ? <Loader2 size={14} className="animate-spin" /> : <Radar size={14} />}
          <span className="hidden sm:inline">Quick scan</span>
          <CornerDownLeft size={12} className="hidden opacity-60 lg:block" aria-hidden />
        </button>
        <button
          type="button"
          className="btn btn-primary rounded-l-none border-l-[color-mix(in_srgb,#000_25%,var(--color-signal))] px-2"
          aria-haspopup="menu"
          aria-expanded={menu}
          aria-label="More investigation modes"
          onClick={() => setMenu((m) => !m)}
        >
          <ChevronDown size={14} />
        </button>
        {menu && (
          <div role="menu" className="panel absolute top-[calc(100%+6px)] right-0 z-40 w-[320px] animate-rise p-1 shadow-[0_16px_48px_rgba(0,0,0,0.55)]">
            <button type="button" role="menuitem" className="flex w-full items-start gap-3 rounded-[2px] px-3 py-2.5 text-left hover:bg-ink-2" onClick={() => void submit("QUICK")}>
              <Radar size={15} className="mt-0.5 text-fg-2" />
              <span>
                <span className="flex items-center gap-2 text-sm font-semibold text-fg-1">
                  Quick scan <Kbd>↵</Kbd>
                </span>
                <span className="mt-0.5 block text-xs text-fg-3">Passive sources only: intelligence feeds, reputation, DNS and registration data. Never touches the target.</span>
              </span>
            </button>
            <button type="button" role="menuitem" className="flex w-full items-start gap-3 rounded-[2px] px-3 py-2.5 text-left hover:bg-ink-2" onClick={() => void submit("DEEP")}>
              <Crosshair />
              <span>
                <span className="flex items-center gap-2 text-sm font-semibold text-fg-1">
                  Deep investigation <Kbd>⇧↵</Kbd>
                  {!canDeep && <Lock size={11} className="text-fg-3" aria-label="Requires operator session" />}
                </span>
                <span className="mt-0.5 block text-xs text-fg-3">Adds every source plus direct TLS, HTTP and mail-policy probes of the target, certificate transparency and DNSSEC.{!canDeep && " Requires an operator session."}</span>
              </span>
            </button>
          </div>
        )}
      </div>
    </form>
  );
}

function Crosshair() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" className="mt-0.5 shrink-0 text-signal" aria-hidden>
      <circle cx="8" cy="8" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="8" cy="8" r="1.6" fill="currentColor" />
      <path d="M8 0.5v3M8 12.5v3M0.5 8h3M12.5 8h3" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}
