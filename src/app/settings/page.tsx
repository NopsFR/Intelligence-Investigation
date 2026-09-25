import Link from "next/link";
import { PROVIDERS } from "@/lib/providers/registry";

export default function SettingsPage() {
  return (
    <div className="mx-auto max-w-[900px] px-4 md:px-6 py-10 space-y-8">
      <div>
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[var(--nops-text-faint)] mb-1">Configuration</p>
        <h1 className="text-2xl font-medium text-[var(--nops-text)]">Settings</h1>
        <p className="text-sm text-[var(--nops-text-dim)] mt-2 max-w-2xl">
          API credentials are configured through server-side environment variables, never through this interface —
          that is what keeps them out of the browser entirely. This page shows what is currently configured. To
          change it, edit <code className="font-mono text-[var(--nops-text)]">.env.local</code> and restart the
          application.
        </p>
      </div>

      <div className="border border-[var(--nops-border)] bg-[var(--nops-bg-panel)]">
        <div className="border-b border-[var(--nops-border)] px-4 py-3">
          <h2 className="font-mono text-xs uppercase tracking-wider text-[var(--nops-text-dim)]">Integrations</h2>
        </div>
        <ul>
          {PROVIDERS.map((p) => (
            <li key={p.meta.id} className="flex items-center justify-between gap-3 border-b border-[var(--nops-border)] last:border-b-0 px-4 py-3">
              <div>
                <p className="font-mono text-sm text-[var(--nops-text)]">{p.meta.name}</p>
                {p.meta.requiresEnv && (
                  <p className="font-mono text-[11px] text-[var(--nops-text-faint)]">
                    {p.meta.requiresEnv.map((e) => `${e}=${"•".repeat(6)}`).join(", ")}
                  </p>
                )}
              </div>
              <span
                className={`rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                  p.isConfigured()
                    ? "text-[var(--nops-green)] border-[#1f4a34] bg-[rgba(63,156,109,0.08)]"
                    : "text-[var(--nops-text-faint)] border-[var(--nops-border)]"
                }`}
              >
                {p.isConfigured() ? "Configured" : "Not configured"}
              </span>
            </li>
          ))}
        </ul>
      </div>

      <p className="font-mono text-xs text-[var(--nops-text-faint)]">
        See <Link href="/observatory" className="underline hover:text-[var(--nops-text-dim)]">API Observatory</Link> to run a live
        connectivity test against each configured provider.
      </p>
    </div>
  );
}
