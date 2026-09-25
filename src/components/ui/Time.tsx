"use client";

import { useEffect, useState } from "react";
import { dateTime, relative } from "@/lib/client/format";
import { usePrefs } from "@/lib/client/prefs";

/** Timestamp that honours the UTC/local preference; relative mode ticks every 30s. */
export function Time({ iso, mode = "relative", seconds = false, className }: { iso?: string | null; mode?: "relative" | "absolute" | "both"; seconds?: boolean; className?: string }) {
  const { prefs } = usePrefs();
  const [, tick] = useState(0);
  useEffect(() => {
    if (mode === "absolute") return;
    const t = setInterval(() => tick((n) => n + 1), 30_000);
    return () => clearInterval(t);
  }, [mode]);
  if (!iso) return <span className={className}>—</span>;
  const abs = dateTime(iso, prefs.tz, seconds);
  return (
    <time dateTime={iso} title={abs} className={className} suppressHydrationWarning>
      {mode === "absolute" ? abs : mode === "both" ? `${abs} · ${relative(iso)}` : relative(iso)}
    </time>
  );
}
