// Safe, local, isolated vulnerability exercises. Every "vulnerable" function
// here is a small, honest simulation of a real bug class running entirely in
// pure JavaScript against in-memory fake data — there is no real SQL engine,
// shell, filesystem, or network call anywhere in this module. Nothing here
// ever touches an external target; it exists purely to let a learner see the
// mechanics of an injection or an access-control bug and then see the fixed
// version reject the same payload.

// ---------------------------------------------------------------- SQL injection

export interface UserRecord {
  id: number;
  username: string;
  password: string;
  role: "admin" | "user";
}

export const SQLI_USERS: UserRecord[] = [
  { id: 1, username: "admin", password: "S3cure!Root99", role: "admin" },
  { id: 2, username: "alice", password: "alice-pw-2024", role: "user" },
  { id: 3, username: "bob", password: "hunter2000", role: "user" },
];

interface WhereClause {
  field?: string;
  literalLeft?: string;
  value: string;
}

/**
 * A tiny WHERE-clause evaluator: OR-separated groups of AND-joined
 * `field='value'` or `'const'='const'` comparisons, with `--` treated as a
 * line comment. This mirrors real SQL operator precedence (AND binds
 * tighter than OR) closely enough to reproduce classic auth-bypass payloads
 * without needing a real SQL engine.
 */
function parseWhere(clause: string): WhereClause[][] {
  const uncommented = clause.split("--")[0];
  return uncommented.split(/\bOR\b/i).map((group) =>
    group
      .split(/\bAND\b/i)
      .map((c) => c.trim())
      .filter(Boolean)
      .map((c): WhereClause => {
        const fieldCmp = c.match(/^(\w+)\s*=\s*'([^']*)'$/);
        if (fieldCmp) return { field: fieldCmp[1], value: fieldCmp[2] };
        const litCmp = c.match(/^'([^']*)'\s*=\s*'([^']*)'$/);
        if (litCmp) return { literalLeft: litCmp[1], value: litCmp[2] };
        return { field: "__unparsed__", value: c };
      }),
  );
}

function evalWhere(groups: WhereClause[][], record: UserRecord): boolean {
  return groups.some((group) =>
    group.every((c) => (c.field !== undefined ? String((record as unknown as Record<string, unknown>)[c.field] ?? "") === c.value : c.literalLeft === c.value)),
  );
}

export interface SqlLoginResult {
  query: string;
  matched: UserRecord | null;
}

/** Vulnerable: the query is built by direct string concatenation. */
export function sqlLoginVulnerable(username: string, password: string): SqlLoginResult {
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const groups = parseWhere(query.slice(query.indexOf("WHERE") + 6));
  const matched = SQLI_USERS.find((u) => evalWhere(groups, u)) ?? null;
  return { query, matched };
}

/** Fixed: username/password are bound as parameters, never concatenated into SQL text. */
export function sqlLoginSafe(username: string, password: string): SqlLoginResult {
  const query = `SELECT * FROM users WHERE username=? AND password=? -- bound parameters`;
  const matched = SQLI_USERS.find((u) => u.username === username && u.password === password) ?? null;
  return { query, matched };
}

// ---------------------------------------------------------------- Path traversal

const UPLOADS_ROOT = "/uploads";

export const TRAVERSAL_FS: Record<string, string> = {
  "/uploads/readme.txt": "Welcome to the uploads folder. Only files placed here should ever be reachable.",
  "/uploads/avatar.png": "(binary image data)",
  "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nnops:x:1000:1000::/home/nops:/bin/bash",
  "/etc/nops/secrets.env": "DATABASE_URL=postgres://[redacted] — this file must never be reachable from /uploads",
};

function normalizePath(p: string): string {
  const stack: string[] = [];
  for (const part of p.split("/").filter(Boolean)) {
    if (part === ".") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  return "/" + stack.join("/");
}

export interface FileReadResult {
  resolvedPath: string;
  content?: string;
  error?: string;
}

/** Vulnerable: concatenates the user path onto the root with no normalization or boundary check. */
export function readUploadedFileVulnerable(userPath: string): FileReadResult {
  const resolvedPath = normalizePath(`${UPLOADS_ROOT}/${userPath}`);
  const content = TRAVERSAL_FS[resolvedPath];
  return content === undefined ? { resolvedPath, error: "No such file" } : { resolvedPath, content };
}

/** Fixed: normalizes the path, then rejects anything that resolves outside the uploads root. */
export function readUploadedFileSafe(userPath: string): FileReadResult {
  const resolvedPath = normalizePath(`${UPLOADS_ROOT}/${userPath}`);
  if (resolvedPath !== UPLOADS_ROOT && !resolvedPath.startsWith(`${UPLOADS_ROOT}/`)) {
    return { resolvedPath, error: "Rejected: path escapes the uploads directory" };
  }
  const content = TRAVERSAL_FS[resolvedPath];
  return content === undefined ? { resolvedPath, error: "No such file" } : { resolvedPath, content };
}

// ---------------------------------------------------------------- IDOR

export interface Invoice {
  id: number;
  ownerId: number;
  amount: number;
  description: string;
}

export const IDOR_CURRENT_USER_ID = 42;

export const IDOR_INVOICES: Invoice[] = [
  { id: 1001, ownerId: 42, amount: 129.5, description: "Annual subscription — your account" },
  { id: 1002, ownerId: 7, amount: 4200, description: "Enterprise contract — ACME Corp" },
  { id: 1003, ownerId: 19, amount: 89.99, description: "Consulting invoice — Globex" },
];

export type InvoiceResult = { invoice: Invoice } | { error: string };

/** Vulnerable: returns any invoice by ID with no ownership check. */
export function getInvoiceVulnerable(id: number): InvoiceResult {
  const invoice = IDOR_INVOICES.find((i) => i.id === id);
  return invoice ? { invoice } : { error: "Not found" };
}

/** Fixed: only returns the invoice if it belongs to the current session's user. */
export function getInvoiceSafe(id: number): InvoiceResult {
  const invoice = IDOR_INVOICES.find((i) => i.id === id);
  if (!invoice) return { error: "Not found" };
  if (invoice.ownerId !== IDOR_CURRENT_USER_ID) return { error: "Forbidden: not your invoice" };
  return { invoice };
}

// ---------------------------------------------------------------- Insecure deserialization

export interface SessionProfile {
  username: string;
  role: "user" | "admin";
}

const TRUSTED_ROLES: Record<string, "user" | "admin"> = { alice: "user", bob: "user", admin: "admin" };

export type ProfileResult = { profile: SessionProfile } | { error: string };

/** Vulnerable: trusts a client-supplied `role` field from the deserialized blob wholesale. */
export function deserializeProfileVulnerable(json: string): ProfileResult {
  let obj: unknown;
  try {
    obj = JSON.parse(json);
  } catch {
    return { error: "Invalid JSON" };
  }
  if (typeof obj !== "object" || obj === null || typeof (obj as Record<string, unknown>).username !== "string") return { error: "Missing username" };
  const rawRole = (obj as Record<string, unknown>).role;
  const role = rawRole === "admin" ? "admin" : "user";
  return { profile: { username: (obj as Record<string, unknown>).username as string, role } };
}

/** Fixed: role is always looked up server-side and never taken from the client blob. */
export function deserializeProfileSafe(json: string): ProfileResult {
  let obj: unknown;
  try {
    obj = JSON.parse(json);
  } catch {
    return { error: "Invalid JSON" };
  }
  if (typeof obj !== "object" || obj === null || typeof (obj as Record<string, unknown>).username !== "string") return { error: "Missing username" };
  const username = (obj as Record<string, unknown>).username as string;
  return { profile: { username, role: TRUSTED_ROLES[username] ?? "user" } };
}

// ---------------------------------------------------------------- Command injection

const CMD_FS: Record<string, string> = {
  "/home/nops/notes.txt": "Remember to rotate the API key on Friday.",
  "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nnops:x:1000:1000::/home/nops:/bin/bash",
};

function runFakeCommand(cmd: string): string {
  const [bin, ...args] = cmd.trim().split(/\s+/);
  if (bin === "cat") return CMD_FS[args[0]] ?? `cat: ${args[0]}: No such file or directory`;
  if (bin === "whoami") return "nops-app";
  if (bin === "echo") return args.join(" ");
  if (bin === "ping") return `PING ${args[args.length - 1] ?? ""}: 1 packet transmitted, 1 received`;
  if (!bin) return "";
  return `${bin}: command not found`;
}

/** Vulnerable: builds a shell command line by concatenation, so `; & |` chain a second command. */
export function pingHostVulnerable(host: string): string {
  const full = `ping -c 1 ${host}`;
  const segments = full
    .split(/[;&|]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return segments.map(runFakeCommand).join("\n");
}

const HOSTNAME_RE = /^[a-zA-Z0-9.-]{1,253}$/;

/** Fixed: the host is validated against a strict allowlist before ever touching a command string. */
export function pingHostSafe(host: string): string {
  if (!HOSTNAME_RE.test(host)) return "Rejected: not a valid hostname (letters, digits, dots and hyphens only)";
  return runFakeCommand(`ping -c 1 ${host}`);
}

// ---------------------------------------------------------------- XSS (shared helper)

export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
