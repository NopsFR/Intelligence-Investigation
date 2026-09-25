"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Search, Zap, Microscope } from "lucide-react";
import { detectObservable } from "@/lib/observables/detect";
import { OBSERVABLE_LABELS } from "@/types/observable";

export function ObservableSearch({ autoFocus = false }: { autoFocus?: boolean }) {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const detected = useMemo(() => (value.trim() ? detectObservable(value) : null), [value]);

  async function submit(mode: "QUICK" | "DEEP") {
    if (!value.trim()) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/investigate", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ observable: value.trim(), mode }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Investigation failed.");
        setSubmitting(false);
        return;
      }
      router.push(`/investigations/${data.investigation.id}`);
    } catch {
      setError("Could not reach the investigation service.");
      setSubmitting(false);
    }
  }

  return (
    <div className="w-full">
      <div className="flex items-center gap-2 rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-panel)] px-3 py-2.5 focus-within:border-[var(--nops-red-dim)]">
        <Search size={16} className="text-[var(--nops-text-faint)] shrink-0" aria-hidden />
        <input
          autoFocus={autoFocus}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !submitting) submit("QUICK");
          }}
          placeholder="Search an IP, domain, URL, hash, CVE or ASN..."
          aria-label="Observable search"
          className="w-full bg-transparent font-mono text-sm text-[var(--nops-text)] placeholder:text-[var(--nops-text-faint)] outline-none"
        />
      </div>

      <div className="mt-2 flex flex-wrap items-center justify-between gap-2 min-h-[28px]">
        <div className="font-mono text-xs text-[var(--nops-text-dim)]">
          {detected ? (
            <span>
              Detected: <span className="text-[var(--nops-text)]">{OBSERVABLE_LABELS[detected.type]}</span>
            </span>
          ) : value.trim() ? (
            <span className="text-[var(--nops-amber)]">Unrecognized observable format</span>
          ) : (
            <span className="text-[var(--nops-text-faint)]">Ready to investigate</span>
          )}
        </div>

        <div className="flex gap-2">
          <button
            disabled={!detected || submitting}
            onClick={() => submit("QUICK")}
            className="inline-flex items-center gap-1.5 rounded border border-[var(--nops-border-strong)] bg-[var(--nops-bg-raised)] px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-[var(--nops-text)] disabled:opacity-40 hover:border-[var(--nops-text-faint)] transition-colors"
          >
            <Zap size={13} /> Quick Scan
          </button>
          <button
            disabled={!detected || submitting}
            onClick={() => submit("DEEP")}
            className="inline-flex items-center gap-1.5 rounded border border-[var(--nops-red-dim)] bg-[var(--nops-red-bg)] px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-[var(--nops-red)] disabled:opacity-40 hover:bg-[rgba(197,40,61,0.16)] transition-colors"
          >
            <Microscope size={13} /> Deep Investigation
          </button>
        </div>
      </div>

      {submitting && (
        <p className="mt-2 font-mono text-xs text-[var(--nops-text-dim)]" role="status">
          Running investigation — contacting providers…
        </p>
      )}
      {error && (
        <p className="mt-2 font-mono text-xs text-[var(--nops-red)]" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
