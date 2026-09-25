"use client";

import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

interface ObservatoryProvider {
  id: string;
  name: string;
  description: string;
  availability: "no-key" | "free-registration" | "quota-limited";
  homepage: string;
  supports: string[];
  configured: boolean;
  lastCheckedAt: string | null;
  lastStatus: string | null;
  lastLatencyMs: number | null;
  lastError: string | null;
}

const AVAILABILITY_LABEL: Record<string, string> = {
  "no-key": "No API key required",
  "free-registration": "Free, requires registration",
  "quota-limited": "Free tier, quota-limited",
};

export default function ObservatoryPage() {
  const [providers, setProviders] = useState<ObservatoryProvider[] | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  async function load() {
    const res = await fetch("/api/observatory");
    const data = await res.json();
    setProviders(data.providers);
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- initial data load on mount
    load();
  }, []);

  async function testConnection(id: string) {
    setTesting(id);
    await fetch(`/api/observatory/${id}/test`, { method: "POST" });
    await load();
    setTesting(null);
  }

  return (
    <div className="mx-auto max-w-[1200px] px-4 md:px-6 py-10 space-y-6">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-1">
          Integration status
        </p>
        <h1 className="text-2xl font-medium text-[var(--nops-text)]">API Observatory</h1>
        <p className="text-sm text-[var(--nops-text-dim)] mt-2 max-w-2xl">
          Every provider used by NOPS, its configuration state, and a live connectivity test. No key, token, or
          authorization header is ever shown here.
        </p>
      </div>

      {!providers ? (
        <p className="font-mono text-sm text-[var(--nops-text-faint)]">Loading…</p>
      ) : (
        <div className="grid md:grid-cols-2 gap-4">
          {providers.map((p) => (
            <div key={p.id} className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)] p-4 flex flex-col gap-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h2 className="font-mono text-sm text-[var(--nops-text)]">{p.name}</h2>
                  <p className="text-xs text-[var(--nops-text-dim)] mt-1">{p.description}</p>
                </div>
                <span
                  className={`shrink-0 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                    p.configured
                      ? "text-[var(--nops-green)] border-[#1f4a34] bg-[rgba(63,156,109,0.08)]"
                      : "text-[var(--nops-text-faint)] border-[var(--nops-border)]"
                  }`}
                >
                  {p.configured ? "Configured" : "Not configured"}
                </span>
              </div>

              <p className="font-mono text-[11px] text-[var(--nops-text-faint)]">{AVAILABILITY_LABEL[p.availability]}</p>

              <div className="flex items-center justify-between font-mono text-[11px] text-[var(--nops-text-dim)] border-t border-[var(--nops-border)] pt-3">
                <span>
                  {p.lastStatus ? (
                    <>
                      {p.lastStatus} {p.lastLatencyMs ? `· ${p.lastLatencyMs}ms` : ""}
                    </>
                  ) : (
                    "Not yet tested"
                  )}
                </span>
                <button
                  onClick={() => testConnection(p.id)}
                  disabled={testing === p.id}
                  className="inline-flex items-center gap-1.5 rounded border border-[var(--nops-border-strong)] px-2 py-1 uppercase tracking-wider hover:text-[var(--nops-text)] disabled:opacity-40"
                >
                  <RefreshCw size={11} className={testing === p.id ? "animate-spin" : ""} />
                  Test connection
                </button>
              </div>
              {p.lastError && <p className="font-mono text-[11px] text-[var(--nops-red)]">{p.lastError}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
