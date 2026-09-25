"use client";

import { ArrowUpRight, Search, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { api, ApiClientError } from "@/lib/client/api";
import { useSession } from "@/lib/client/session";
import { SEVERITY_COLOR } from "@/components/ui/badges";
import { Mark } from "@/components/investigation/views/common";
import { ErrorNote, Panel, Stat } from "@/components/ui/primitives";
import { Chip, LocalFindings, Mono } from "../common";

interface HeaderCheck {
  id: string;
  header: string;
  status: "pass" | "warn" | "fail" | "info";
  value?: string;
  note: string;
}
interface TextResource {
  path: string;
  present: boolean;
  status?: number;
  size?: number;
  excerpt?: string;
  contentType?: string;
}
interface Finding {
  rule: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  rationale?: string;
  evidence: string;
}
interface Report {
  url: string;
  finalUrl: string;
  status: number;
  https: boolean;
  hops: { url: string; status: number; location?: string; server?: string; latencyMs: number }[];
  title?: string;
  server?: string;
  poweredBy?: string;
  tls?: { protocol: string | null; authorized: boolean; authorizationError?: string };
  headers: Record<string, string>;
  setCookies: { raw: string; name: string; secure: boolean; httpOnly: boolean; sameSite?: string }[];
  checks: HeaderCheck[];
  robots: TextResource;
  securityTxt: TextResource & { fields?: Record<string, string[]> };
  sitemap: TextResource & { urlCount?: number };
  cors: { tested: boolean; reflectsOrigin: boolean; allowCredentialsWithWildcard: boolean; allowOrigin?: string; allowCredentials?: string };
  technologies: string[];
  findings: Finding[];
  bodyTruncated: boolean;
  durationMs: number;
}

export function WebSecurity() {
  const operator = useSession().session?.operator ?? false;
  const [url, setUrl] = useState("");
  const [state, setState] = useState<{ phase: "idle" } | { phase: "loading" } | { phase: "done"; report: Report } | { phase: "error"; message: string }>({ phase: "idle" });

  const run = async () => {
    if (!url.trim()) return;
    setState({ phase: "loading" });
    try {
      const target = /^https?:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`;
      const report = await api<Report>(`/api/analysis/web?url=${encodeURIComponent(target)}`);
      setState({ phase: "done", report });
    } catch (err) {
      setState({ phase: "error", message: (err as ApiClientError).message });
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel>
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
        >
          <input className="input h-9 min-w-[260px] flex-1" placeholder="https://example.com" value={url} onChange={(e) => setUrl(e.target.value)} aria-label="URL to scan" disabled={!operator} />
          <button type="submit" className="btn btn-primary" disabled={!operator || state.phase === "loading"}>
            <Search size={14} /> Scan
          </button>
        </form>
        {!operator && <p className="mt-2 text-xs text-warn">This scan contacts the target directly. Unlock an operator session to use it — only scan sites you are authorized to test.</p>}
        <p className="mt-2 text-xs text-fg-4">Headers, cookies, TLS, CORS, security.txt, robots.txt, sitemap.xml and technology indicators. No exploitation, no scanning of arbitrary ports or paths beyond these well-known locations.</p>
      </Panel>

      {state.phase === "error" && <ErrorNote title="Scan failed">{state.message}</ErrorNote>}
      {state.phase === "done" && <Report report={state.report} />}
    </div>
  );
}

function Report({ report: r }: { report: Report }) {
  const worst = r.findings[0]?.severity;
  const passCount = r.checks.filter((c) => c.status === "pass").length;
  return (
    <div className="flex flex-col gap-4">
      <section className="panel panel-ticks animate-rise">
        <div className="flex flex-wrap items-start gap-x-6 gap-y-2 border-b border-line-1 p-[var(--panel-pad)]">
          <div className="min-w-0 flex-1">
            <div className="label mb-1">Web security · {r.durationMs} ms</div>
            <h2 className="display truncate text-xl text-fg-1">{r.title ?? r.finalUrl}</h2>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-fg-3">
              <Mono className="text-fg-2">{r.finalUrl}</Mono>
              {r.finalUrl !== r.url && <span className="text-fg-4">(redirected from {r.url})</span>}
              <Chip tone={r.status < 400 ? "ok" : "err"}>{r.status}</Chip>
            </div>
          </div>
        </div>
        <div className="grid gap-px bg-line-1 sm:grid-cols-2 xl:grid-cols-4">
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Highest finding" value={worst ? <span style={{ color: SEVERITY_COLOR[worst] }}>{worst[0] + worst.slice(1).toLowerCase()}</span> : "None"} sub={`${r.findings.length} findings`} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Header checks" value={<span className="tabular">{passCount}/{r.checks.length}</span>} sub="passing" />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="TLS" value={r.https ? (r.tls?.authorized ? "Valid" : r.tls ? "Untrusted" : "—") : "None (HTTP)"} sub={r.tls?.protocol ?? (r.https ? "" : "connection is not encrypted")} />
          </div>
          <div className="bg-ink-1 p-[var(--panel-pad)]">
            <Stat label="Server" value={r.server ?? "not announced"} sub={r.technologies.slice(0, 3).join(", ") || "no technology indicators"} />
          </div>
        </div>
      </section>

      <section className="panel">
        <LocalFindings findings={r.findings.map((f) => ({ id: f.rule, severity: f.severity, title: f.title, detail: [f.description, f.rationale].filter(Boolean).join(" "), evidence: f.evidence ? [f.evidence] : [], basis: "structure" }))} />
      </section>

      {r.hops.length > 1 && (
        <section className="panel p-[var(--panel-pad)]">
          <h3 className="label mb-2">Redirect chain</h3>
          <ol className="flex flex-col gap-1.5">
            {r.hops.map((h, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2 text-xs">
                <Mono className="text-fg-4">{i + 1}.</Mono>
                <Mono className="break-all text-fg-1">{h.url}</Mono>
                <Chip tone={h.status < 400 ? "neutral" : "err"}>{h.status}</Chip>
                {h.server && <span className="text-fg-4">{h.server}</span>}
              </li>
            ))}
          </ol>
        </section>
      )}

      <section className="panel">
        <h3 className="label px-[var(--panel-pad)] pt-3">Security headers</h3>
        <ul className="divide-y divide-line-1">
          {r.checks.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-2.5 px-[var(--panel-pad)] py-2.5">
              <Mark state={c.status}>{c.header}</Mark>
              <span className="text-xs text-fg-3">{c.note}</span>
              {c.value && <Mono className="ml-auto max-w-[420px] truncate text-[11px] text-fg-4">{c.value}</Mono>}
            </li>
          ))}
        </ul>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel p-[var(--panel-pad)]">
          <h3 className="label mb-2">Cookies</h3>
          {!r.setCookies.length ? (
            <p className="text-sm text-fg-3">No cookies set on this response.</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {r.setCookies.map((c, i) => (
                <li key={i} className="text-xs">
                  <Mono className="text-fg-1">{c.name}</Mono>
                  <span className="ml-2 flex flex-wrap gap-1">
                    {c.secure ? <Chip tone="ok">Secure</Chip> : <Chip tone="warn">no Secure</Chip>}
                    {c.httpOnly ? <Chip tone="ok">HttpOnly</Chip> : <Chip tone="warn">no HttpOnly</Chip>}
                    <Chip tone={c.sameSite?.toLowerCase() === "strict" ? "ok" : c.sameSite ? "neutral" : "warn"}>{c.sameSite ? `SameSite=${c.sameSite}` : "no SameSite"}</Chip>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="panel p-[var(--panel-pad)]">
          <h3 className="label mb-2">CORS</h3>
          {!r.cors.tested ? (
            <p className="text-sm text-fg-3">Could not be probed.</p>
          ) : r.cors.allowOrigin ? (
            <div className="flex flex-col gap-1 text-xs">
              <div>
                <Mono className="text-fg-1">Access-Control-Allow-Origin</Mono>: <Mono className="text-fg-2">{r.cors.allowOrigin}</Mono>
              </div>
              {r.cors.allowCredentials && (
                <div>
                  <Mono className="text-fg-1">Access-Control-Allow-Credentials</Mono>: <Mono className="text-fg-2">{r.cors.allowCredentials}</Mono>
                </div>
              )}
              <p className="mt-1 text-fg-3">{r.cors.reflectsOrigin ? "Reflects any Origin sent to it." : r.cors.allowOrigin === "*" ? "Allows any origin." : "Restricted to specific origins."}</p>
            </div>
          ) : (
            <p className="text-sm text-fg-3">No Access-Control-Allow-Origin header — cross-origin reads are blocked by the browser&apos;s default same-origin policy.</p>
          )}
        </section>

        <TextResourceCard title="robots.txt" resource={r.robots} />
        <TextResourceCard title="security.txt" resource={r.securityTxt} extra={r.securityTxt.fields && Object.keys(r.securityTxt.fields).length > 0 ? Object.entries(r.securityTxt.fields).map(([k, v]) => `${k}: ${v.join(", ")}`) : undefined} />
        <TextResourceCard title="sitemap.xml" resource={r.sitemap} extra={r.sitemap.urlCount !== undefined ? [`${r.sitemap.urlCount} URLs`] : undefined} />

        <section className="panel p-[var(--panel-pad)]">
          <h3 className="label mb-2">Technology indicators</h3>
          {r.technologies.length ? (
            <div className="flex flex-wrap gap-1.5">
              {r.technologies.map((t) => (
                <Chip key={t} tone="ice">
                  {t}
                </Chip>
              ))}
            </div>
          ) : (
            <p className="text-sm text-fg-3">No indicators recognised from headers or the page body.</p>
          )}
          {r.poweredBy && <p className="mt-2 text-xs text-fg-4">X-Powered-By: {r.poweredBy}</p>}
        </section>
      </div>

      {r.bodyTruncated && (
        <p className="flex items-center gap-1.5 text-xs text-fg-4">
          <ShieldAlert size={12} /> The response body was larger than the analysis limit and was truncated; technology detection may be incomplete.
        </p>
      )}
    </div>
  );
}

function TextResourceCard({ title, resource, extra }: { title: string; resource: TextResource; extra?: string[] }) {
  return (
    <section className="panel p-[var(--panel-pad)]">
      <div className="mb-2 flex items-center gap-2">
        <h3 className="label">{title}</h3>
        {resource.present ? <Chip tone="ok">present</Chip> : <Chip>not found</Chip>}
      </div>
      {resource.present ? (
        <>
          {extra && (
            <ul className="mb-2 flex flex-col gap-0.5 text-xs text-fg-3">
              {extra.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}
          <pre className="mono max-h-40 overflow-auto rounded-[2px] bg-ink-0 p-2 text-[11px] whitespace-pre-wrap text-fg-2 shadow-[inset_0_0_0_1px_var(--color-line-1)]">{resource.excerpt?.slice(0, 2000)}</pre>
          <p className="mt-1.5 flex items-center gap-1 text-xs text-fg-4">
            <ArrowUpRight size={10} /> {resource.path}
          </p>
        </>
      ) : (
        <p className="text-sm text-fg-3">Not found at {resource.path}.</p>
      )}
    </section>
  );
}
