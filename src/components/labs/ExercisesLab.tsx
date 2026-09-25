"use client";

import { ShieldAlert, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import {
  deserializeProfileSafe,
  deserializeProfileVulnerable,
  escapeHtml,
  getInvoiceSafe,
  getInvoiceVulnerable,
  IDOR_CURRENT_USER_ID,
  IDOR_INVOICES,
  pingHostSafe,
  pingHostVulnerable,
  readUploadedFileSafe,
  readUploadedFileVulnerable,
  sqlLoginSafe,
  sqlLoginVulnerable,
} from "@/lib/labs/exercises";
import { Tabs } from "@/components/ui/overlays";
import { Panel } from "@/components/ui/primitives";
import { Mono } from "../analysis/common";

const EXERCISES = [
  { id: "sqli", label: "SQL injection" },
  { id: "xss", label: "Cross-site scripting" },
  { id: "traversal", label: "Path traversal" },
  { id: "idor", label: "IDOR" },
  { id: "deser", label: "Insecure deserialization" },
  { id: "cmdi", label: "Command injection" },
];

export function ExercisesLab() {
  const [tab, setTab] = useState("sqli");
  return (
    <div className="flex flex-col gap-4">
      <div role="alert" className="flex items-start gap-3 rounded-[3px] border px-3 py-2.5 text-sm" style={{ borderColor: "color-mix(in srgb, var(--color-ice) 35%, transparent)", background: "color-mix(in srgb, var(--color-ice) 7%, transparent)" }}>
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-ice" aria-hidden />
        <div>
          <div className="font-semibold text-fg-1">Local and isolated, not a real target</div>
          <div className="mt-0.5 text-fg-2">
            Every exercise here runs against fake in-memory data with hand-written vulnerable and fixed functions. Nothing is executed as a real shell command, real SQL, or real file access, and nothing ever leaves your browser or touches a network. These exist to show the mechanics of a bug class, not to attack anything.
          </div>
        </div>
      </div>

      <Tabs label="Exercise" value={tab} onChange={setTab} items={EXERCISES} />
      {tab === "sqli" && <SqliExercise />}
      {tab === "xss" && <XssExercise />}
      {tab === "traversal" && <TraversalExercise />}
      {tab === "idor" && <IdorExercise />}
      {tab === "deser" && <DeserExercise />}
      {tab === "cmdi" && <CmdiExercise />}
    </div>
  );
}

function ResultBanner({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2.5 rounded-[3px] border px-3 py-2.5 text-sm" style={{ borderColor: `color-mix(in srgb, ${ok ? "var(--color-err)" : "var(--color-ok)"} 35%, transparent)`, background: `color-mix(in srgb, ${ok ? "var(--color-err)" : "var(--color-ok)"} 7%, transparent)` }}>
      {ok ? <ShieldAlert size={15} className="mt-0.5 shrink-0 text-err" aria-hidden /> : <ShieldCheck size={15} className="mt-0.5 shrink-0 text-ok" aria-hidden />}
      <div className="min-w-0 flex-1 text-fg-1">{children}</div>
    </div>
  );
}

function VulnCode({ children }: { children: string }) {
  return <pre className="mono overflow-x-auto rounded-[3px] border border-line-2 bg-ink-2 px-3 py-2.5 text-[12px] text-fg-2">{children}</pre>;
}

function SqliExercise() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const vuln = useMemo(() => sqlLoginVulnerable(username, password), [username, password]);
  const safe = useMemo(() => sqlLoginSafe(username, password), [username, password]);

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Vulnerable login">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`SELECT * FROM users WHERE username='\${username}' AND password='\${password}'`}</VulnCode>
          <input className="input" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} aria-label="SQL injection username" />
          <input className="input" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} aria-label="SQL injection password" />
          <div className="mono text-xs break-all text-fg-3">{vuln.query}</div>
          {vuln.matched ? (
            <ResultBanner ok>
              Logged in as <strong>{vuln.matched.username}</strong> ({vuln.matched.role}) — try <Mono className="text-fg-1">admin&apos; --</Mono> as the username, or <Mono className="text-fg-1">&apos; OR &apos;1&apos;=&apos;1&apos; --</Mono>.
            </ResultBanner>
          ) : (
            <ResultBanner ok={false}>No match.</ResultBanner>
          )}
        </div>
      </Panel>
      <Panel title="Fixed: parameterized query">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`db.query("SELECT * FROM users WHERE username=? AND password=?", [username, password])`}</VulnCode>
          <p className="text-xs text-fg-3">Same input, run through the fixed version — the injection payload is treated as a literal username, not SQL syntax.</p>
          <div className="mono text-xs break-all text-fg-3">{safe.query}</div>
          {safe.matched ? (
            <ResultBanner ok>
              Logged in as <strong>{safe.matched.username}</strong>.
            </ResultBanner>
          ) : (
            <ResultBanner ok={false}>No match — the payload does not bypass parameter binding.</ResultBanner>
          )}
        </div>
      </Panel>
    </div>
  );
}

const XSS_VECTOR_PATTERNS: { id: string; label: string; re: RegExp }[] = [
  { id: "script-tag", label: "<script> element", re: /<script[\s>]/i },
  { id: "event-handler", label: "inline event handler (onerror=, onload=, …)", re: /\bon\w+\s*=/i },
  { id: "js-url", label: "javascript: URL", re: /javascript:/i },
  { id: "svg-onload", label: "<svg> with an embedded handler", re: /<svg[^>]*on\w+/i },
];

/** Rendered fully inert: `sandbox=""` (no `allow-scripts`) disables script execution
 * regardless of CSP, so this iframe exists purely to show the resulting DOM shape —
 * nothing in it can ever run, navigate, or make a request that matters. */
function InertFrame({ html, label }: { html: string; label: string }) {
  const srcDoc = `<!doctype html><body style="margin:0;padding:8px;background:#0a0a0a;color:#e6e6e6;font:12px monospace;word-break:break-all">${html}</body>`;
  return <iframe title={label} className="h-[90px] w-full rounded-[2px] bg-[#0a0a0a]" sandbox="" srcDoc={srcDoc} />;
}

function XssExercise() {
  const [input, setInput] = useState("");
  const vulnHtml = `Comment: ${input}`;
  const safeHtml = `Comment: ${escapeHtml(input)}`;
  const vectors = XSS_VECTOR_PATTERNS.filter((v) => v.re.test(input));

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Vulnerable: reflects input as raw HTML">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`element.innerHTML = "Comment: " + userInput`}</VulnCode>
          <input
            className="input"
            placeholder={`Try <img src=x onerror="steal(document.cookie)">`}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="XSS payload input"
          />
          <div className="rounded-[3px] border border-line-2 bg-ink-2 p-1">
            <InertFrame html={vulnHtml} label="Resulting DOM (sandboxed, cannot execute)" />
          </div>
          {vectors.length ? (
            <ResultBanner ok>
              Your input becomes real DOM, not text — it contains: {vectors.map((v) => v.label).join(", ")}. In a page without this app&apos;s CSP, that would execute attacker JavaScript with the victim&apos;s session.
            </ResultBanner>
          ) : (
            <p className="text-xs text-fg-3">No known script vector in this input yet — it&apos;s still inserted as raw HTML, just not one of the patterns above.</p>
          )}
          <p className="text-xs text-fg-3">This frame has <Mono className="text-fg-1">sandbox=&quot;&quot;</Mono> (no <Mono className="text-fg-1">allow-scripts</Mono>), so nothing in it can run even to demonstrate the bug — it only renders the DOM shape your payload would build.</p>
        </div>
      </Panel>
      <Panel title="Fixed: HTML-escaped before rendering">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`element.textContent = "Comment: " + userInput  // or escapeHtml() before innerHTML`}</VulnCode>
          <div className="rounded-[3px] border border-line-2 bg-ink-2 p-1">
            <InertFrame html={safeHtml} label="Escaped render" />
          </div>
          <p className="text-xs text-fg-3">
            Escaped output: <Mono className="text-fg-1 break-all">{escapeHtml(input) || "(empty)"}</Mono> — every character that could open a tag or attribute is now inert text, whatever the payload.
          </p>
        </div>
      </Panel>
    </div>
  );
}

function TraversalExercise() {
  const [path, setPath] = useState("readme.txt");
  const vuln = readUploadedFileVulnerable(path);
  const safe = readUploadedFileSafe(path);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Vulnerable: naive path join">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`fs.readFile("/uploads/" + userPath)`}</VulnCode>
          <input className="input mono" placeholder="readme.txt" value={path} onChange={(e) => setPath(e.target.value)} aria-label="Path traversal input" />
          <p className="text-xs text-fg-3">
            Try <Mono className="text-fg-1">../etc/nops/secrets.env</Mono>
          </p>
          <div className="mono text-xs break-all text-fg-3">resolved: {vuln.resolvedPath}</div>
          {vuln.content ? <ResultBanner ok>{vuln.content}</ResultBanner> : <ResultBanner ok={false}>{vuln.error}</ResultBanner>}
        </div>
      </Panel>
      <Panel title="Fixed: normalize, then verify the boundary">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`const resolved = normalize("/uploads/" + userPath);\nif (!resolved.startsWith("/uploads/")) reject();`}</VulnCode>
          <div className="mono text-xs break-all text-fg-3">resolved: {safe.resolvedPath}</div>
          {safe.content ? <ResultBanner ok>{safe.content}</ResultBanner> : <ResultBanner ok={false}>{safe.error}</ResultBanner>}
        </div>
      </Panel>
    </div>
  );
}

function IdorExercise() {
  const [id, setId] = useState(1002);
  const vuln = getInvoiceVulnerable(id);
  const safe = getInvoiceSafe(id);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Vulnerable: no ownership check">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`GET /invoices/:id  →  db.invoice.find({ id })`}</VulnCode>
          <p className="text-xs text-fg-3">
            Signed in as user #{IDOR_CURRENT_USER_ID}. Your own invoice is {IDOR_INVOICES.find((i) => i.ownerId === IDOR_CURRENT_USER_ID)?.id}. Try incrementing the ID.
          </p>
          <input className="input" type="number" value={id} onChange={(e) => setId(Number(e.target.value))} aria-label="Invoice ID" />
          {"invoice" in vuln ? (
            <ResultBanner ok={vuln.invoice.ownerId !== IDOR_CURRENT_USER_ID}>
              #{vuln.invoice.id} — {vuln.invoice.description} — <strong>${vuln.invoice.amount.toFixed(2)}</strong> (owner #{vuln.invoice.ownerId})
            </ResultBanner>
          ) : (
            <ResultBanner ok={false}>{vuln.error}</ResultBanner>
          )}
        </div>
      </Panel>
      <Panel title="Fixed: ownership enforced server-side">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`db.invoice.find({ id, ownerId: session.userId })`}</VulnCode>
          {"invoice" in safe ? (
            <ResultBanner ok>
              #{safe.invoice.id} — {safe.invoice.description}
            </ResultBanner>
          ) : (
            <ResultBanner ok={false}>{safe.error}</ResultBanner>
          )}
        </div>
      </Panel>
    </div>
  );
}

function DeserExercise() {
  const [json, setJson] = useState('{"username":"alice","role":"user"}');
  const vuln = deserializeProfileVulnerable(json);
  const safe = deserializeProfileSafe(json);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Vulnerable: trusts the client blob">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`const profile = JSON.parse(clientBlob);\nsession.role = profile.role; // trusted as-is`}</VulnCode>
          <textarea className="input mono min-h-[90px] text-[12px]" value={json} onChange={(e) => setJson(e.target.value)} aria-label="Profile JSON" spellCheck={false} />
          <p className="text-xs text-fg-3">
            Change <Mono className="text-fg-1">&quot;role&quot;:&quot;user&quot;</Mono> to <Mono className="text-fg-1">&quot;role&quot;:&quot;admin&quot;</Mono>.
          </p>
          {"profile" in vuln ? (
            <ResultBanner ok={vuln.profile.role === "admin"}>
              {vuln.profile.username} signed in as <strong>{vuln.profile.role}</strong>
            </ResultBanner>
          ) : (
            <ResultBanner ok={false}>{vuln.error}</ResultBanner>
          )}
        </div>
      </Panel>
      <Panel title="Fixed: role resolved from a trusted source">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`const profile = JSON.parse(clientBlob);\nsession.role = trustedRoles[profile.username] ?? "user";`}</VulnCode>
          {"profile" in safe ? (
            <ResultBanner ok={false}>
              {safe.profile.username} signed in as <strong>{safe.profile.role}</strong> — the client&apos;s role claim was ignored.
            </ResultBanner>
          ) : (
            <ResultBanner ok={false}>{safe.error}</ResultBanner>
          )}
        </div>
      </Panel>
    </div>
  );
}

function CmdiExercise() {
  const [host, setHost] = useState("");
  const vuln = pingHostVulnerable(host);
  const safe = pingHostSafe(host);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Vulnerable: concatenated shell command">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`exec("ping -c 1 " + host)`}</VulnCode>
          <input className="input mono" placeholder="example.com" value={host} onChange={(e) => setHost(e.target.value)} aria-label="Host for ping" />
          <p className="text-xs text-fg-3">
            Try <Mono className="text-fg-1">example.com; cat /etc/passwd</Mono>
          </p>
          <pre className="mono overflow-x-auto rounded-[3px] border border-line-2 bg-ink-2 px-3 py-2.5 text-[12px] text-fg-1">{vuln || "(no output)"}</pre>
        </div>
      </Panel>
      <Panel title="Fixed: hostname allowlist, never concatenated">
        <div className="flex flex-col gap-3 p-[var(--panel-pad)]">
          <VulnCode>{`if (!/^[a-zA-Z0-9.-]{1,253}$/.test(host)) reject();\nexec(["ping", "-c", "1", host]) // argv array, no shell`}</VulnCode>
          <pre className="mono overflow-x-auto rounded-[3px] border border-line-2 bg-ink-2 px-3 py-2.5 text-[12px] text-fg-1">{safe || "(no output)"}</pre>
        </div>
      </Panel>
    </div>
  );
}
