"use client";

import { Activity, Database, ExternalLink, KeyRound, Loader2, Lock, Palette, ShieldCheck, Terminal, Trash2, Unlock } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState, type ReactNode } from "react";
import type { SettingsData } from "@/lib/db/settings";
import { api, type ApiClientError } from "@/lib/client/api";
import { cx } from "@/lib/client/cx";
import { usePrefs } from "@/lib/client/prefs";
import { useSession } from "@/lib/client/session";
import { Prov } from "@/components/ui/badges";
import { useToast } from "@/components/ui/overlays";
import { ErrorNote, Segmented, Toggle } from "@/components/ui/primitives";
import { Time } from "@/components/ui/Time";

const SECTIONS = [
  { id: "providers", label: "Providers", icon: <KeyRound size={14} /> },
  { id: "security", label: "Security", icon: <ShieldCheck size={14} /> },
  { id: "database", label: "Database", icon: <Database size={14} /> },
  { id: "appearance", label: "Appearance", icon: <Palette size={14} /> },
  { id: "developer", label: "Developer", icon: <Terminal size={14} /> },
];

function Block({ title, description, children }: { title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel panel-ticks">
      <header className="border-b border-line-1 px-[var(--panel-pad)] py-3">
        <h2 className="text-sm font-semibold text-fg-1">{title}</h2>
        {description && <p className="mt-0.5 text-xs text-fg-3">{description}</p>}
      </header>
      <div className="p-[var(--panel-pad)]">{children}</div>
    </section>
  );
}

function Row({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="grid gap-1 border-b border-line-1 py-2.5 last:border-0 sm:grid-cols-[220px_minmax(0,1fr)] sm:gap-4">
      <div className="text-xs text-fg-3">{label}</div>
      <div className="min-w-0 text-sm text-fg-1">{children}</div>
    </div>
  );
}

function Flag({ on, yes, no }: { on: boolean; yes: string; no: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span aria-hidden className="h-[7px] w-[7px] rotate-45" style={{ background: on ? "var(--color-ok)" : "transparent", boxShadow: on ? undefined : "inset 0 0 0 1px var(--color-fg-4)" }} />
      {on ? yes : no}
    </span>
  );
}

function Providers({ data }: { data: SettingsData }) {
  return (
    <div className="flex flex-col gap-4">
      <Block
        title="API credentials"
        description={
          <>
            Keys are read from server environment variables and never sent to the browser. Set them in your deployment’s environment (for Vercel: Project → Settings → Environment Variables) and redeploy. Sources without keys stay <span className="text-fg-1">Not configured</span> and are never called.
          </>
        }
      >
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Requirement</th>
                <th>Environment variable</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.keys.map((k) => (
                <tr key={k.provider}>
                  <td>
                    <div className="flex items-center gap-2.5">
                      <Prov id={k.provider} className="w-[38px] justify-center" />
                      <span className="text-sm text-fg-1">{k.name}</span>
                    </div>
                    {k.benefit && <div className="mt-1 pl-[48px] text-xs text-fg-4">{k.benefit}</div>}
                  </td>
                  <td className="align-middle text-xs text-fg-2">{k.requirement === "required" ? "Required" : "Optional"}</td>
                  <td className="align-middle">
                    <div className="flex flex-col gap-0.5">
                      {k.env.map((e, i) => (
                        <code key={e} className={cx("mono text-[11.5px]", i === 0 ? "text-fg-1" : "text-fg-4")}>
                          {e}
                          {i > 0 && " (alias)"}
                        </code>
                      ))}
                    </div>
                  </td>
                  <td className="align-middle text-xs">
                    {k.present ? <span className="mono text-fg-2">••••••••••••  set</span> : <span className="text-fg-4">Not set</span>}
                  </td>
                  <td className="text-right align-middle">
                    <a href={k.signup} target="_blank" rel="noopener noreferrer" className="btn btn-ghost btn-sm">
                      Get key <ExternalLink size={11} />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex justify-end">
          <Link href="/observatory" className="btn btn-sm">
            <Activity size={12} /> Test connections in the Observatory
          </Link>
        </div>
      </Block>
    </div>
  );
}

function Security({ data }: { data: SettingsData }) {
  const { session, unlock, lock } = useSession();
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  const router = useRouter();

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await unlock(token);
      setToken("");
      toast({ kind: "success", title: "Operator session unlocked", body: "Valid for 12 hours on this browser." });
      router.refresh();
    } catch (e) {
      setError((e as ApiClientError).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Block title="Operator session" description="Deep investigations (which contact targets), deletions and IOC library changes require an operator session. Everything else is read-only and open.">
        {session?.operator ? (
          <div className="flex flex-wrap items-center gap-3">
            <Unlock size={15} className="text-ok" />
            <span className="text-sm text-fg-1">Unlocked{session.expiresAt ? <> · expires <Time iso={session.expiresAt} /></> : data.security.operatorConfigured ? "" : " (development mode: no token configured)"}</span>
            {data.security.operatorConfigured && (
              <button type="button" className="btn btn-sm ml-auto" onClick={() => void lock().then(() => router.refresh())}>
                <Lock size={12} /> Lock
              </button>
            )}
          </div>
        ) : data.security.operatorConfigured ? (
          <form className="flex flex-col gap-2 sm:max-w-[520px]" onSubmit={(e) => (e.preventDefault(), void submit())}>
            <label htmlFor="operator-token" className="text-xs text-fg-3">
              Operator token (NOPS_ADMIN_TOKEN)
            </label>
            <div className="flex gap-2">
              <input id="operator-token" type="password" autoComplete="current-password" className="input mono text-[12px]" value={token} onChange={(e) => setToken(e.target.value)} placeholder="••••••••••••••••" />
              <button type="submit" className="btn btn-primary" disabled={busy || !token}>
                {busy ? <Loader2 size={13} className="animate-spin" /> : <Unlock size={13} />} Unlock
              </button>
            </div>
            {error && <p className="text-xs text-err">{error}</p>}
            <p className="text-xs text-fg-4">The token is exchanged for an HttpOnly, SameSite=Strict signed cookie. Attempts are rate limited.</p>
          </form>
        ) : (
          <ErrorNote title="No operator token configured">Operator actions are disabled on this deployment. Set NOPS_ADMIN_TOKEN (a long random string) in the server environment to enable them.</ErrorNote>
        )}
      </Block>
      <Block title="Posture" description="How this deployment protects itself and the targets it analyses.">
        <Row label="Operator token">
          <Flag on={data.security.operatorConfigured} yes="Configured" no="Not configured" />
        </Row>
        <Row label="Session signing secret">
          <Flag on={data.security.sessionSecretSet} yes="Dedicated secret (NOPS_SESSION_SECRET)" no="Derived from the operator token" />
        </Row>
        <Row label="Private mode">
          <Flag on={data.security.privateMode} yes="Everything requires an operator session" no="Read-only access is public (NOPS_PRIVATE=1 to restrict)" />
        </Row>
        <Row label="Content Security Policy">{data.security.csp}</Row>
        <Row label="CSRF">State-changing requests must be same-origin (Sec-Fetch-Site / Origin) and JSON-encoded.</Row>
        <Row label="Outbound requests to targets">
          Only http/https on ports {data.security.targetPorts.join(", ")}. Every connection resolves the hostname and refuses private, loopback, link-local, CGNAT, multicast, reserved, cloud-metadata and translation ranges at connect time (no DNS-rebinding window). Each redirect is re-validated; bodies are capped at 512 KB; each hop times out.
        </Row>
        <Row label="Non-public observables">Private and special-purpose addresses are never sent to external intelligence sources.</Row>
      </Block>
      <Block title="Rate limits" description="Shared across all server instances via the database.">
        {data.security.limits.map((l) => (
          <Row key={l.name} label={l.name}>
            <span className="text-fg-2">{l.rule}</span>
          </Row>
        ))}
      </Block>
    </div>
  );
}

function DatabaseSection({ data, operator }: { data: SettingsData; operator: boolean }) {
  const d = data.database;
  const toast = useToast();
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const purge = async (all: boolean) => {
    setBusy(true);
    try {
      const r = await api<{ deleted: number }>(`/api/settings/cache${all ? "?all=1" : ""}`, { method: "DELETE" });
      toast({ kind: "success", title: `${r.deleted} cache entries removed` });
      router.refresh();
    } catch (e) {
      toast({ kind: "error", title: "Could not clear the cache", body: (e as ApiClientError).message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-col gap-4">
      <Block title="Connection">
        <Row label="Status">
          <Flag on={d.connected} yes={`Connected · ${d.latencyMs} ms round trip`} no="Unreachable" />
          {d.error && <div className="mt-1 text-xs text-err">{d.error}</div>}
        </Row>
        <Row label="Engine">{d.engine}</Row>
        <Row label="Host">{d.host ? <span className="mono text-[12px]">{d.host}</span> : <span className="text-fg-4">{operator ? "—" : "Hidden without an operator session"}</span>}</Row>
        {d.database && (
          <Row label="Database">
            <span className="mono text-[12px]">{d.database}</span>
          </Row>
        )}
      </Block>
      {d.connected && (
        <>
          <Block title="Contents">
            <dl className="grid gap-px overflow-hidden rounded-[2px] bg-line-1 sm:grid-cols-3 lg:grid-cols-4">
              {Object.entries(d.counts).map(([k, v]) => (
                <div key={k} className="bg-ink-0 px-3 py-2.5">
                  <dt className="text-[11px] text-fg-4">{k.replace(/([A-Z])/g, " $1").toLowerCase()}</dt>
                  <dd className="display tabular text-lg text-fg-1">{v.toLocaleString("en-GB")}</dd>
                </div>
              ))}
            </dl>
          </Block>
          <Block title="Provider cache" description="Successful and empty answers are cached per source TTL. Re-running with “bypass cache” ignores it.">
            <Row label="Entries">
              {d.cache.active.toLocaleString("en-GB")} active · {d.cache.expired.toLocaleString("en-GB")} expired
            </Row>
            <div className="mt-3 flex gap-2">
              <button type="button" className="btn btn-sm" disabled={busy || !operator} onClick={() => void purge(false)}>
                <Trash2 size={12} /> Purge expired
              </button>
              <button type="button" className="btn btn-sm" disabled={busy || !operator} onClick={() => void purge(true)}>
                <Trash2 size={12} /> Clear all
              </button>
              {!operator && <span className="self-center text-xs text-fg-4">Operator session required</span>}
            </div>
          </Block>
          <Block title="Migrations">
            {d.migrations.length ? (
              d.migrations.map((m) => (
                <Row key={m.name} label={<Time iso={m.appliedAt} mode="absolute" />}>
                  <span className="mono text-[12px]">{m.name}</span>
                </Row>
              ))
            ) : (
              <p className="text-sm text-fg-3">No migration history table found.</p>
            )}
          </Block>
        </>
      )}
    </div>
  );
}

function Appearance() {
  const { prefs, setPref, reset } = usePrefs();
  return (
    <Block title="Appearance" description="Stored in this browser only.">
      <Row label="Density">
        <Segmented label="Density" value={prefs.density} onChange={(v) => setPref("density", v)} options={[{ value: "comfortable", label: "Comfortable" }, { value: "compact", label: "Compact" }]} />
      </Row>
      <Row label="Motion">
        <Segmented label="Motion" value={prefs.motion} onChange={(v) => setPref("motion", v)} options={[{ value: "system", label: "Follow system" }, { value: "reduced", label: "Reduced" }, { value: "full", label: "Full" }]} />
      </Row>
      <Row label="Timestamps">
        <Segmented label="Timestamps" value={prefs.tz} onChange={(v) => setPref("tz", v)} options={[{ value: "utc", label: "UTC" }, { value: "local", label: "Local time" }]} />
      </Row>
      <Row label="Navigation rail">
        <Toggle checked={prefs.rail === "collapsed"} onChange={(v) => setPref("rail", v ? "collapsed" : "expanded")} label="Collapse to icons" />
      </Row>
      <div className="mt-3">
        <button type="button" className="btn btn-ghost btn-sm" onClick={reset}>
          Reset to defaults
        </button>
      </div>
    </Block>
  );
}

function Developer({ data }: { data: SettingsData }) {
  const endpoints: [string, string, string][] = [
    ["POST", "/api/investigations", "Start an investigation {observable, mode: QUICK|DEEP, type?, fresh?}"],
    ["GET", "/api/investigations", "List (q, type, status, severity, cursor)"],
    ["GET", "/api/investigations/:id", "Full record; poll while status is RUNNING"],
    ["GET", "/api/investigations/:id/raw?provider=", "Stored raw payload for one source"],
    ["GET", "/api/investigations/:id/export?format=", "json | csv | md"],
    ["GET", "/api/observatory", "Source health, usage and quotas"],
    ["POST", "/api/observatory/:provider/test", "Real connection test"],
    ["GET", "/api/ioc/export?format=", "csv | json | stix"],
    ["GET", "/api/attack/search?q=", "Search ATT&CK"],
    ["GET", "/api/health", "Liveness and database reachability"],
  ];
  return (
    <div className="flex flex-col gap-4">
      <Block title="Deployment">
        <Row label="Version">{data.deployment.version}</Row>
        <Row label="Commit">{data.deployment.commit ? <span className="mono">{data.deployment.commit}</span> : <span className="text-fg-4">Unknown (local build)</span>}</Row>
        <Row label="Environment">{data.deployment.environment}</Row>
        <Row label="Region">{data.deployment.region ?? <span className="text-fg-4">—</span>}</Row>
        <Row label="Runtime">
          <span className="mono">Node {data.deployment.node}</span>
        </Row>
      </Block>
      <Block title="HTTP API" description="JSON over HTTPS. State-changing calls must be same-origin; operator actions need the session cookie.">
        <div className="overflow-x-auto">
          <table className="table">
            <tbody>
              {endpoints.map(([m, p, d]) => (
                <tr key={`${m}${p}`}>
                  <td className="mono w-[60px] text-[11px] text-fg-3">{m}</td>
                  <td className="mono text-[12px] whitespace-nowrap text-fg-1">{p}</td>
                  <td className="text-xs text-fg-3">{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Block>
      <Block title="Command line" description="The same engine runs without a database — useful for scripting and for checking provider behaviour from another network.">
        <pre className="mono overflow-x-auto rounded-[2px] bg-ink-0 p-3 text-[12px] text-fg-1 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{`npm run investigate -- 8.8.8.8
npm run investigate -- example.com --deep --json > result.json`}</pre>
      </Block>
    </div>
  );
}

export function Settings({ data }: { data: SettingsData }) {
  const params = useSearchParams();
  const router = useRouter();
  const path = usePathname();
  const section = SECTIONS.some((s) => s.id === params.get("section")) ? params.get("section")! : "providers";
  return (
    <div className="grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)]">
      <nav aria-label="Settings sections" className="panel h-fit p-1.5 lg:sticky lg:top-[calc(var(--topbar-h)+16px)]">
        <ul className="flex gap-1 overflow-x-auto lg:flex-col">
          {SECTIONS.map((s) => (
            <li key={s.id} className="shrink-0">
              <button type="button" onClick={() => router.replace(`${path}?section=${s.id}`, { scroll: false })} aria-current={s.id === section ? "page" : undefined} className={cx("flex w-full items-center gap-2.5 rounded-[2px] px-2.5 py-2 text-left text-sm transition-colors", s.id === section ? "bg-ink-3 text-fg-1" : "text-fg-3 hover:bg-ink-2 hover:text-fg-1")}>
                {s.icon}
                {s.label}
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <div key={section} className="min-w-0 animate-fade">
        {section === "providers" && <Providers data={data} />}
        {section === "security" && <Security data={data} />}
        {section === "database" && <DatabaseSection data={data} operator={data.security.operator} />}
        {section === "appearance" && <Appearance />}
        {section === "developer" && <Developer data={data} />}
      </div>
    </div>
  );
}
