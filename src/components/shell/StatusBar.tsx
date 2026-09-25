"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { cx } from "@/lib/client/cx";
import { usePrefs } from "@/lib/client/prefs";

interface Status {
  db: { ok: boolean; latencyMs?: number };
  running: number;
  sources: { external: number; configured: number; states: Record<string, number> };
  commit?: string;
  region?: string;
}

function Clock() {
  const { prefs } = usePrefs();
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- client clock starts after hydration
    setNow(new Date());
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  if (!now) return null;
  const p = (n: number) => String(n).padStart(2, "0");
  const text = prefs.tz === "utc" ? `${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())} UTC` : `${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`;
  return <span className="tabular">{text}</span>;
}

/** Bottom status line: real database reachability, source health and in-flight work. */
export function StatusBar() {
  const [status, setStatus] = useState<Status | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await fetch("/api/status", { cache: "no-store" });
        if (!res.ok) throw new Error(String(res.status));
        const data = (await res.json()) as Status;
        if (alive) {
          setStatus(data);
          setFailed(false);
        }
      } catch {
        if (alive) setFailed(true);
      }
    };
    void load();
    const t = setInterval(load, 30_000);
    const onVisible = () => document.visibilityState === "visible" && void load();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      alive = false;
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);

  const connected = status?.sources.states.CONNECTED ?? 0;
  const degraded = status ? Object.entries(status.sources.states).filter(([k]) => !["CONNECTED", "NOT_CONFIGURED", "UNTESTED"].includes(k)).reduce((a, [, v]) => a + v, 0) : 0;

  return (
    <footer style={{ viewTransitionName: "shell-status" }} className="no-print fixed inset-x-0 bottom-0 z-30 flex h-[var(--statusbar-h)] items-center gap-4 overflow-hidden border-t border-line-1 bg-ink-1 px-3 text-[10.5px] text-fg-3 lg:pl-[calc(var(--rail-w)+12px)]" aria-label="System status">
      <span className="flex items-center gap-1.5" title={status?.db.ok ? `Database reachable (${status.db.latencyMs} ms)` : "Database unreachable"}>
        <span className={cx("dot h-[6px] w-[6px]")} style={{ color: failed ? "var(--color-fg-4)" : status?.db.ok ? "var(--color-ok)" : status ? "var(--color-err)" : "var(--color-fg-4)" }} />
        <span className="mono">DB</span>
        {status?.db.ok && <span className="mono tabular text-fg-4">{status.db.latencyMs}ms</span>}
        {failed && <span className="text-fg-4">status unavailable</span>}
      </span>
      {status && (
        <Link href="/observatory" className="flex items-center gap-1.5 hover:text-fg-1" title="External sources: connected / configured / total">
          <span className="mono">SOURCES</span>
          <span className="mono tabular text-fg-2">{connected}</span>
          <span className="text-fg-4">connected ·</span>
          <span className="mono tabular">{status.sources.configured}/{status.sources.external}</span>
          <span className="text-fg-4">configured</span>
          {degraded > 0 && <span className="mono text-warn">· {degraded} degraded</span>}
        </Link>
      )}
      {status && status.running > 0 && (
        <Link href="/investigations?status=RUNNING" className="flex items-center gap-1.5 text-ice hover:text-fg-1">
          <span className="dot dot-live h-[6px] w-[6px]" />
          <span className="mono tabular">{status.running}</span> running
        </Link>
      )}
      <span className="ml-auto hidden items-center gap-4 sm:flex">
        {status?.region && <span className="mono uppercase">{status.region}</span>}
        {status?.commit && <span className="mono">{status.commit}</span>}
        <span className="mono">
          <Clock />
        </span>
      </span>
    </footer>
  );
}
