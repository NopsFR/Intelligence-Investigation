"use client";

import { Eye, EyeOff, KeyRound, RefreshCw, Shield, ShieldAlert, ShieldCheck, Wand2 } from "lucide-react";
import { useMemo, useState } from "react";
import { analyzePassword, generatePassphrase, generatePassword, passphraseEntropyBits, type PasswordGeneratorOptions } from "@/lib/labs/password";
import { hashText } from "@/lib/labs/crypto";
import { api, ApiClientError } from "@/lib/client/api";
import { CopyButton, ErrorNote, Panel } from "@/components/ui/primitives";
import { Chip, Mono } from "../analysis/common";

const TIER_LABEL: Record<string, string> = { "very-weak": "Very weak", weak: "Weak", fair: "Fair", strong: "Strong", "very-strong": "Very strong" };
const TIER_TONE: Record<string, "err" | "warn" | "ok"> = { "very-weak": "err", weak: "err", fair: "warn", strong: "ok", "very-strong": "ok" };
const TIER_WIDTH: Record<string, string> = { "very-weak": "20%", weak: "40%", fair: "60%", strong: "80%", "very-strong": "100%" };

async function sha1Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export function PasswordLab() {
  return (
    <div className="flex flex-col gap-4">
      <div role="alert" className="flex items-start gap-3 rounded-[3px] border px-3 py-2.5 text-sm" style={{ borderColor: "color-mix(in srgb, var(--color-ice) 35%, transparent)", background: "color-mix(in srgb, var(--color-ice) 7%, transparent)" }}>
        <Shield size={16} className="mt-0.5 shrink-0 text-ice" aria-hidden />
        <div>
          <div className="font-semibold text-fg-1">Everything below runs in your browser</div>
          <div className="mt-0.5 text-fg-2">
            Strength analysis, generation, and hashing never leave this page. The one network call — the breach check — sends only a 5-character SHA-1 prefix (k-anonymity), never the password. Nothing you type here is stored or logged.
          </div>
        </div>
      </div>
      <AnalyzerPanel />
      <GeneratorPanel />
      <HashDemoPanel />
    </div>
  );
}

function AnalyzerPanel() {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const analysis = useMemo(() => analyzePassword(pw), [pw]);
  const [breach, setBreach] = useState<{ phase: "idle" } | { phase: "loading" } | { phase: "done"; count: number } | { phase: "error"; message: string }>({ phase: "idle" });

  const checkBreach = async () => {
    if (!pw) return;
    setBreach({ phase: "loading" });
    try {
      const hash = await sha1Hex(pw);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const res = await api<{ suffixes: { suffix: string; count: number }[] }>("/api/intel/exposure/password", { method: "POST", json: { prefix } });
      const match = res.suffixes.find((s) => s.suffix === suffix);
      setBreach({ phase: "done", count: match?.count ?? 0 });
    } catch (err) {
      setBreach({ phase: "error", message: (err as ApiClientError).message });
    }
  };

  const clear = () => {
    setPw("");
    setBreach({ phase: "idle" });
  };

  return (
    <Panel title="Strength analysis" bodyClassName="p-0">
      <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
        <div className="relative">
          <input
            type={show ? "text" : "password"}
            className="input h-9 w-full pr-16 font-mono"
            placeholder="Type a password to analyse"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            autoComplete="off"
            aria-label="Password to analyse"
            spellCheck={false}
          />
          <div className="absolute top-1/2 right-2 flex -translate-y-1/2 items-center gap-1">
            <button type="button" className="btn btn-ghost btn-icon btn-sm" onClick={() => setShow((s) => !s)} aria-label={show ? "Hide password" : "Show password"}>
              {show ? <EyeOff size={13} /> : <Eye size={13} />}
            </button>
            {pw && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={clear}>
                Clear
              </button>
            )}
          </div>
        </div>

        {pw && (
          <>
            <div>
              <div className="mb-1 flex items-center justify-between">
                <Chip tone={TIER_TONE[analysis.tier]}>{TIER_LABEL[analysis.tier]}</Chip>
                <span className="mono text-xs text-fg-4">~{analysis.entropyBits.toFixed(0)} bits of entropy (structural estimate)</span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-2">
                <div className="h-full rounded-full transition-[width]" style={{ width: TIER_WIDTH[analysis.tier], background: TIER_TONE[analysis.tier] === "ok" ? "var(--color-ok)" : TIER_TONE[analysis.tier] === "warn" ? "var(--color-warn)" : "var(--color-err)" }} />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs text-fg-3 sm:grid-cols-4">
              <span>Length: <span className="text-fg-1">{analysis.length}</span></span>
              <span>Lowercase: <span className="text-fg-1">{analysis.charset.lower ? "yes" : "no"}</span></span>
              <span>Uppercase: <span className="text-fg-1">{analysis.charset.upper ? "yes" : "no"}</span></span>
              <span>Digits: <span className="text-fg-1">{analysis.charset.digit ? "yes" : "no"}</span></span>
              <span>Symbols: <span className="text-fg-1">{analysis.charset.symbol ? "yes" : "no"}</span></span>
            </div>

            {analysis.patterns.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <div className="label text-fg-3">Weaknesses found</div>
                {analysis.patterns.map((p) => (
                  <div key={p.id} className="flex items-start gap-2 text-xs">
                    <ShieldAlert size={13} className="mt-0.5 shrink-0 text-err" />
                    <div>
                      <span className="text-fg-1">{p.label}</span>
                      <span className="block text-fg-4">{p.detail}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex flex-col gap-1.5">
              <div className="label text-fg-3">Suggestions</div>
              <ul className="flex flex-col gap-1">
                {analysis.suggestions.map((s, i) => (
                  <li key={i} className="text-xs text-fg-2">
                    · {s}
                  </li>
                ))}
              </ul>
            </div>

            <div className="border-t border-line-1 pt-3">
              <button type="button" className="btn btn-ghost btn-sm" disabled={breach.phase === "loading"} onClick={() => void checkBreach()}>
                Check against Pwned Passwords (k-anonymity)
              </button>
              {breach.phase === "error" && (
                <div className="mt-2">
                  <ErrorNote title="Could not complete the check">{breach.message}</ErrorNote>
                </div>
              )}
              {breach.phase === "done" &&
                (breach.count > 0 ? (
                  <p className="mt-2 flex items-center gap-2 text-sm text-err">
                    <ShieldAlert size={14} /> Seen in {breach.count.toLocaleString()} known breach dump{breach.count === 1 ? "" : "s"}.
                  </p>
                ) : (
                  <p className="mt-2 flex items-center gap-2 text-sm text-ok">
                    <ShieldCheck size={14} /> Not found in Pwned Passwords.
                  </p>
                ))}
            </div>
          </>
        )}
        <p className="text-xs text-fg-4">This is a structural estimate, not a guarantee — real-world crackability also depends on the attacker&apos;s wordlists, hardware, and how the site itself stores the password.</p>
      </div>
    </Panel>
  );
}

function GeneratorPanel() {
  const [length, setLength] = useState(16);
  const [opts, setOpts] = useState<Omit<PasswordGeneratorOptions, "length">>({ lower: true, upper: true, digits: true, symbols: true });
  const [generated, setGenerated] = useState("");
  const [genError, setGenError] = useState<string | null>(null);
  const [wordCount, setWordCount] = useState(5);
  const [passphrase, setPassphrase] = useState("");

  const makePassword = () => {
    try {
      setGenError(null);
      setGenerated(generatePassword({ length, ...opts }));
    } catch (err) {
      setGenError((err as Error).message);
      setGenerated("");
    }
  };
  const makePassphrase = () => setPassphrase(generatePassphrase(wordCount));

  return (
    <Panel title="Generators" bodyClassName="p-0">
      <div className="grid gap-4 p-[var(--panel-pad)] sm:grid-cols-2">
        <div className="flex flex-col gap-2.5">
          <div className="label text-fg-3">Strong password</div>
          <div className="flex items-center gap-2">
            <input type="number" min={4} max={128} className="input h-9 w-20" value={length} onChange={(e) => setLength(Math.min(128, Math.max(4, Number(e.target.value) || 4)))} aria-label="Password length" />
            <span className="text-xs text-fg-3">characters</span>
          </div>
          <div className="flex flex-wrap gap-3 text-xs text-fg-2">
            {(["lower", "upper", "digits", "symbols"] as const).map((k) => (
              <label key={k} className="flex items-center gap-1.5">
                <input type="checkbox" checked={opts[k]} onChange={(e) => setOpts((o) => ({ ...o, [k]: e.target.checked }))} /> {k}
              </label>
            ))}
          </div>
          <button type="button" className="btn btn-primary btn-sm w-fit" onClick={makePassword}>
            <Wand2 size={13} /> Generate
          </button>
          {genError && <ErrorNote title="Cannot generate">{genError}</ErrorNote>}
          {generated && (
            <div className="flex items-center gap-1.5 rounded-[2px] bg-ink-0 px-2.5 py-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
              <Mono className="min-w-0 flex-1 truncate text-fg-1">{generated}</Mono>
              <CopyButton value={generated} label="Copy generated password" />
              <button type="button" className="btn btn-ghost btn-icon btn-sm" onClick={makePassword} aria-label="Regenerate">
                <RefreshCw size={12} />
              </button>
            </div>
          )}
        </div>

        <div className="flex flex-col gap-2.5">
          <div className="label text-fg-3">Passphrase</div>
          <div className="flex items-center gap-2">
            <input type="number" min={3} max={10} className="input h-9 w-20" value={wordCount} onChange={(e) => setWordCount(Math.min(10, Math.max(3, Number(e.target.value) || 3)))} aria-label="Number of words" />
            <span className="text-xs text-fg-3">words · ~{passphraseEntropyBits(wordCount).toFixed(0)} bits</span>
          </div>
          <button type="button" className="btn btn-primary btn-sm w-fit" onClick={makePassphrase}>
            <Wand2 size={13} /> Generate
          </button>
          {passphrase && (
            <div className="flex items-center gap-1.5 rounded-[2px] bg-ink-0 px-2.5 py-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">
              <Mono className="min-w-0 flex-1 truncate text-fg-1">{passphrase}</Mono>
              <CopyButton value={passphrase} label="Copy generated passphrase" />
              <button type="button" className="btn btn-ghost btn-icon btn-sm" onClick={makePassphrase} aria-label="Regenerate">
                <RefreshCw size={12} />
              </button>
            </div>
          )}
          <p className="text-xs text-fg-4">Drawn from a fixed local word list using the Web Crypto RNG — never Math.random.</p>
        </div>
      </div>
    </Panel>
  );
}

function HashDemoPanel() {
  const [text, setText] = useState("");
  const [results, setResults] = useState<Record<string, string>>({});

  const run = async (t: string) => {
    setText(t);
    if (!t) {
      setResults({});
      return;
    }
    const algs = ["MD5", "SHA-1", "SHA-256"] as const;
    const out: Record<string, string> = {};
    for (const alg of algs) out[alg] = await hashText(alg, t);
    setResults(out);
  };

  return (
    <Panel title="Hashing demonstration" meta={<KeyRound size={13} className="text-fg-4" />} bodyClassName="p-0">
      <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
        <p className="text-xs text-fg-3">
          Hashing is one-way and <em>not</em> encryption — you cannot recover the input from the hash. Real password storage additionally salts and uses a slow, memory-hard function (Argon2id/bcrypt/scrypt), not a fast general-purpose hash like these.
        </p>
        <input className="input mono h-9" placeholder="Type text to hash" value={text} onChange={(e) => void run(e.target.value)} spellCheck={false} aria-label="Text to hash" />
        {Object.entries(results).map(([alg, hash]) => (
          <div key={alg} className="flex items-center gap-2">
            <span className="w-16 shrink-0 text-xs text-fg-3">{alg}</span>
            <Mono className="min-w-0 flex-1 truncate text-fg-1">{hash}</Mono>
            <CopyButton value={hash} label={`Copy ${alg} hash`} />
          </div>
        ))}
      </div>
    </Panel>
  );
}
