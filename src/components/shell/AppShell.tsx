"use client";

import { ChevronsLeft, ChevronsRight, Lock, Menu, Search, Unlock, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { cx } from "@/lib/client/cx";
import { usePrefs } from "@/lib/client/prefs";
import { useSession } from "@/lib/client/session";
import { CommandBar } from "./CommandBar";
import { CommandPalette } from "./CommandPalette";
import { Wordmark } from "./Logo";
import { NAV, isActive } from "./nav";
import { StatusBar } from "./StatusBar";

function RailNav({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const path = usePathname();
  return (
    <nav aria-label="Primary" className="flex-1 overflow-y-auto px-2 py-3">
      {NAV.map((group) => (
        <div key={group.group} className="mb-4">
          {!collapsed ? <div className="label px-2.5 pb-1.5 text-fg-4">{group.group}</div> : <div className="mx-auto mb-2 h-px w-5 bg-line-2" aria-hidden />}
          <ul className="flex flex-col gap-px">
            {group.items.map((item) => {
              const active = isActive(item, path);
              const Icon = item.icon;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    title={collapsed ? item.label : undefined}
                    className={cx(
                      "group relative flex h-[32px] items-center gap-3 rounded-[3px] text-sm transition-colors",
                      collapsed ? "justify-center px-0" : "px-2.5",
                      active ? "bg-ink-3 text-fg-1" : "text-fg-3 hover:bg-ink-2 hover:text-fg-1"
                    )}
                  >
                    {active && <span aria-hidden className="absolute top-[7px] bottom-[7px] -left-2 w-[2px] rounded-r-[1px] bg-signal" />}
                    <Icon size={16} strokeWidth={active ? 2 : 1.75} className="shrink-0" />
                    {!collapsed && <span className="truncate font-medium">{item.label}</span>}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function OperatorChip({ collapsed }: { collapsed: boolean }) {
  const { session } = useSession();
  const operator = session?.operator ?? false;
  return (
    <Link
      href="/settings?section=security"
      className={cx("flex h-[34px] items-center gap-2.5 rounded-[3px] border border-line-1 text-xs transition-colors hover:border-line-3", collapsed ? "justify-center" : "px-2.5")}
      title={operator ? "Operator session active" : "Read-only session — unlock operator actions"}
    >
      {operator ? <Unlock size={13} className="text-ok" /> : <Lock size={13} className="text-fg-3" />}
      {!collapsed && (
        <span className="min-w-0 flex-1">
          <span className="block font-medium text-fg-1">{operator ? "Operator" : "Read-only"}</span>
        </span>
      )}
    </Link>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { prefs, setPref } = usePrefs();
  const [palette, setPalette] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const router = useRouter();
  const path = usePathname();
  const collapsed = prefs.rail === "collapsed";

  const closePalette = useCallback(() => setPalette(false), []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- close the mobile nav on navigation
    setDrawer(false);
  }, [path]);

  // ⌘K / Ctrl+K palette, and "g x" navigation chords.
  useEffect(() => {
    let chord = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
        return;
      }
      const target = e.target as HTMLElement;
      if (target.closest("input, textarea, select, [contenteditable=true], [role=dialog]") || e.metaKey || e.ctrlKey || e.altKey) return;
      if (chord) {
        chord = false;
        clearTimeout(timer);
        const item = NAV.flatMap((g) => g.items).find((i) => i.shortcut?.toLowerCase() === `g ${e.key.toLowerCase()}`);
        if (item) {
          e.preventDefault();
          router.push(item.href);
        }
        return;
      }
      if (e.key === "g") {
        chord = true;
        timer = setTimeout(() => (chord = false), 900);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      clearTimeout(timer);
    };
  }, [router]);

  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only z-[80] rounded-[3px] bg-ink-3 px-3 py-2 text-sm focus:not-sr-only focus:fixed focus:top-2 focus:left-2">
        Skip to content
      </a>

      {/* Desktop rail */}
      <aside style={{ viewTransitionName: "shell-rail" }} className="fixed inset-y-0 left-0 z-30 hidden w-[var(--rail-w)] flex-col border-r border-line-1 bg-ink-1 transition-[width] duration-200 ease-[var(--ease-out-quint)] lg:flex">
        <div className={cx("flex h-[var(--topbar-h)] items-center border-b border-line-1", collapsed ? "justify-center" : "px-4")}>
          <Link href="/" aria-label="NOPS home">
            <Wordmark collapsed={collapsed} />
          </Link>
        </div>
        <RailNav collapsed={collapsed} />
        <div className="flex flex-col gap-2 border-t border-line-1 p-2 pb-[calc(var(--statusbar-h)+8px)]">
          <OperatorChip collapsed={collapsed} />
          <button type="button" className={cx("btn btn-ghost btn-sm", collapsed ? "btn-icon mx-auto" : "justify-start")} onClick={() => setPref("rail", collapsed ? "expanded" : "collapsed")} aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}>
            {collapsed ? <ChevronsRight size={14} /> : <ChevronsLeft size={14} />}
            {!collapsed && <span className="text-fg-3">Collapse</span>}
          </button>
        </div>
      </aside>

      {/* Mobile navigation drawer */}
      {drawer && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 animate-fade bg-black/60" onClick={() => setDrawer(false)} aria-hidden />
          <aside className="absolute inset-y-0 left-0 flex w-[260px] animate-[rise_220ms_var(--ease-out-quint)] flex-col border-r border-line-2 bg-ink-1" aria-label="Navigation">
            <div className="flex h-[var(--topbar-h)] items-center justify-between border-b border-line-1 px-4">
              <Wordmark />
              <button type="button" className="btn btn-ghost btn-icon btn-sm" onClick={() => setDrawer(false)} aria-label="Close navigation">
                <X size={15} />
              </button>
            </div>
            <RailNav collapsed={false} onNavigate={() => setDrawer(false)} />
            <div className="border-t border-line-1 p-2">
              <OperatorChip collapsed={false} />
            </div>
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col transition-[padding] duration-200 ease-[var(--ease-out-quint)] lg:pl-[var(--rail-w)]">
        <header style={{ viewTransitionName: "shell-topbar" }} className="sticky top-0 z-20 flex h-[var(--topbar-h)] items-center gap-2 border-b border-line-1 bg-[color-mix(in_srgb,var(--color-ink-0)_88%,transparent)] px-3 backdrop-blur-md sm:px-4">
          <button type="button" className="btn btn-ghost btn-icon lg:hidden" onClick={() => setDrawer(true)} aria-label="Open navigation">
            <Menu size={16} />
          </button>
          <Link href="/" className="mr-1 lg:hidden" aria-label="NOPS home">
            <Wordmark collapsed />
          </Link>
          <div className="hidden min-w-0 flex-1 sm:flex">
            <CommandBar onOpenPalette={() => setPalette(true)} />
          </div>
          <button type="button" className="btn ml-auto sm:hidden" onClick={() => setPalette(true)} aria-label="Search and investigate">
            <Search size={14} /> Investigate
          </button>
        </header>

        <main id="main" className="min-w-0 flex-1 pb-[calc(var(--statusbar-h)+24px)]">
          {children}
        </main>
      </div>

      <StatusBar />
      <CommandPalette open={palette} onClose={closePalette} />
    </div>
  );
}
