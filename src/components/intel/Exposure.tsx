"use client";

import { Eye, EyeOff, KeyRound, Search, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api, ApiClientError } from "@/lib/client/api";
import { registrableDomain } from "@/lib/observables/detect";
import { ErrorNote } from "@/components/ui/primitives";
import { Chip, Mono } from "../analysis/common";
import { Time } from "../ui/Time";

interface DomainBreach {
  name: string;
  title: string;
  breachDate?: string;
  addedDate?: string;
  pwnCount?: number;
  dataClasses?: string[];
  verified?: boolean;
  sensitive?: boolean;
  retired?: boolean;
  description?: string;
}
interface DomainResult {
  domain: string;
  status: "confirmed-exposure" | "no-result";
  note?: string;
  fetchedAt: string;
  source: string;
  breaches: DomainBreach[];
}

async function sha1Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function Exposure() {
  return (
    <div className="flex flex-col gap-4">
      <DomainExposure />
      <PasswordExposure />
    </div>
  );
}

function DomainExposure() {
  const [domain, setDomain] = useState("");
  const [state, setState] = useState<{ phase: "idle" } | { phase: "loading" } | { phase: "done"; result: DomainResult } | { phase: "error"; message: string }>({ phase: "idle" });

  const run = async (raw: string) => {
    const d = registrableDomain(raw.trim().toLowerCase());
    if (!d) {
      setState({ phase: "error", message: "Enter a valid domain, e.g. example.com." });
      return;
    }
    setState({ phase: "loading" });
    try {
      const result = await api<DomainResult>(`/api/intel/exposure/domain?domain=${encodeURIComponent(d)}`);
      setState({ phase: "done", result });
    } catch (err) {
      setState({ phase: "error", message: (err as ApiClientError).message });
    }
  };

  return (
    <section className="panel panel-ticks">
      <header className="flex items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <ShieldAlert size={14} className="text-fg-3" />
        <h2 className="label text-fg-2">Domain breach exposure</h2>
      </header>
      <div className="p-[var(--panel-pad)]">
        <p className="mb-3 max-w-2xl text-sm text-fg-3">Checks HIBP&apos;s public breach catalogue for breaches attributed to a domain. This confirms exposure when found — it never proves a domain is unaffected, since not every breach records a domain, and HIBP does not index every breach.</p>
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(domain);
          }}
        >
          <input className="input h-9 max-w-sm flex-1" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} aria-label="Domain to check" />
          <button type="submit" className="btn btn-primary" disabled={state.phase === "loading"}>
            <Search size={14} /> Check
          </button>
        </form>

        {state.phase === "error" && (
          <div className="mt-3">
            <ErrorNote title="Could not complete the check">{state.message}</ErrorNote>
          </div>
        )}
        {state.phase === "done" && (
          <div className="mt-4">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              {state.result.status === "confirmed-exposure" ? (
                <Chip tone="err">Confirmed exposure — {state.result.breaches.length} breach{state.result.breaches.length === 1 ? "" : "es"}</Chip>
              ) : (
                <Chip tone="ok">No result in the catalogue</Chip>
              )}
              <span className="text-xs text-fg-4">
                {state.result.source} · fetched <Time iso={state.result.fetchedAt} />
              </span>
            </div>
            {state.result.note && <p className="mb-3 max-w-2xl text-xs text-fg-3">{state.result.note}</p>}
            {state.result.breaches.length > 0 && (
              <ul className="flex flex-col divide-y divide-line-1">
                {state.result.breaches.map((b) => (
                  <li key={b.name} className="py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-fg-1">{b.title}</span>
                      {b.verified === false && <Chip tone="warn">unverified</Chip>}
                      {b.sensitive && <Chip tone="warn">sensitive</Chip>}
                      {b.retired && <Chip>retired</Chip>}
                      {b.breachDate && <Mono className="text-xs text-fg-4">{b.breachDate}</Mono>}
                      {b.pwnCount !== undefined && <span className="text-xs text-fg-4">{b.pwnCount.toLocaleString()} accounts</span>}
                    </div>
                    {b.description && <p className="mt-1 max-w-2xl text-xs text-fg-3" dangerouslySetInnerHTML={{ __html: b.description.replace(/<a /g, '<a rel="noopener noreferrer nofollow" target="_blank" ') }} />}
                    {b.dataClasses && b.dataClasses.length > 0 && (
                      <div className="mt-1.5 flex flex-wrap gap-1">
                        {b.dataClasses.map((c) => (
                          <Chip key={c}>{c}</Chip>
                        ))}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function PasswordExposure() {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [state, setState] = useState<{ phase: "idle" } | { phase: "loading" } | { phase: "done"; count: number } | { phase: "error"; message: string }>({ phase: "idle" });

  const check = async () => {
    if (!pw) return;
    setState({ phase: "loading" });
    try {
      const hash = await sha1Hex(pw);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const res = await api<{ suffixes: { suffix: string; count: number }[] }>("/api/intel/exposure/password", { method: "POST", json: { prefix } });
      const match = res.suffixes.find((s) => s.suffix === suffix);
      setState({ phase: "done", count: match?.count ?? 0 });
    } catch (err) {
      setState({ phase: "error", message: (err as ApiClientError).message });
    }
  };

  return (
    <section className="panel panel-ticks">
      <header className="flex items-center gap-2 border-b border-line-1 px-[var(--panel-pad)] py-2.5">
        <KeyRound size={14} className="text-fg-3" />
        <h2 className="label text-fg-2">Password exposure (k-anonymity)</h2>
      </header>
      <div className="p-[var(--panel-pad)]">
        <p className="mb-3 max-w-2xl text-sm text-fg-3">
          Your browser computes the SHA-1 hash locally and sends only its first 5 characters to Pwned Passwords, which returns every hash sharing that prefix (typically 500–1000). Your browser finds the match — the full hash and the password itself never leave this device.
        </p>
        <form
          className="flex max-w-sm gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void check();
          }}
        >
          <div className="relative flex-1">
            <input type={show ? "text" : "password"} className="input h-9 w-full pr-9" placeholder="Password to check" value={pw} onChange={(e) => setPw(e.target.value)} aria-label="Password to check" autoComplete="off" />
            <button type="button" className="absolute top-1/2 right-2 -translate-y-1/2 text-fg-4 hover:text-fg-1" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}>
              {show ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
          <button type="submit" className="btn btn-primary" disabled={!pw || state.phase === "loading"}>
            Check
          </button>
        </form>
        {state.phase === "error" && (
          <div className="mt-3">
            <ErrorNote title="Could not complete the check">{state.message}</ErrorNote>
          </div>
        )}
        {state.phase === "done" &&
          (state.count > 0 ? (
            <p className="mt-4 flex items-center gap-2 text-sm text-err">
              <ShieldAlert size={15} /> Seen in {state.count.toLocaleString()} known breach dump{state.count === 1 ? "" : "s"}. Do not use this password.
            </p>
          ) : (
            <p className="mt-4 flex items-center gap-2 text-sm text-ok">
              <ShieldCheck size={15} /> Not found in Pwned Passwords. Absence there is not a guarantee of strength or of safety elsewhere.
            </p>
          ))}
      </div>
    </section>
  );
}

