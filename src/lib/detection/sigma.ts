import { parse as parseYaml } from "yaml";

// Sigma rules: parsing and validation, evaluation against events the user
// supplies, and conversion to SIEM query languages. A rule "matches" only
// when it has actually been evaluated against those events.

export class SigmaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SigmaError";
  }
}

type Scalar = string | number | boolean | null;

export interface Matcher {
  field: string | null;
  modifiers: string[];
  values: Scalar[];
}

export type Search = { kind: "and"; matchers: Matcher[] } | { kind: "or"; groups: Matcher[][] } | { kind: "keywords"; values: Scalar[]; modifiers: string[] };

export interface SigmaRule {
  title: string;
  id?: string;
  status?: string;
  description?: string;
  author?: string;
  date?: string;
  references: string[];
  tags: string[];
  attack: string[];
  level?: string;
  logsource: { product?: string; category?: string; service?: string };
  falsepositives: string[];
  fields: string[];
  searches: Record<string, Search>;
  condition: string;
  warnings: string[];
}

const KNOWN_MODIFIERS = new Set(["contains", "startswith", "endswith", "all", "re", "i", "m", "s", "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "windash", "cidr", "lt", "lte", "gt", "gte", "exists", "cased", "fieldref"]);
const LEVELS = ["informational", "low", "medium", "high", "critical"];
const STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];

function toScalars(v: unknown): Scalar[] {
  if (Array.isArray(v)) return v.map((x) => (typeof x === "object" && x !== null ? JSON.stringify(x) : (x as Scalar)));
  if (v === undefined) return [];
  return [typeof v === "object" && v !== null ? JSON.stringify(v) : (v as Scalar)];
}

function parseMatchers(obj: Record<string, unknown>): Matcher[] {
  return Object.entries(obj).map(([key, value]) => {
    const [field, ...modifiers] = key.split("|");
    for (const m of modifiers) if (!KNOWN_MODIFIERS.has(m)) throw new SigmaError(`Unsupported modifier '${m}' on ${field}${m === "expand" ? " (placeholders need a pipeline)" : ""}`);
    return { field: field || null, modifiers, values: toScalars(value) };
  });
}

export function parseSigma(source: string): SigmaRule[] {
  const docs: unknown[] = [];
  try {
    for (const part of source.split(/^---\s*$/m)) if (part.trim()) docs.push(parseYaml(part));
  } catch (e) {
    throw new SigmaError(`YAML: ${(e as Error).message}`);
  }
  if (!docs.length) throw new SigmaError("No rule found");
  return docs.map((raw, i) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new SigmaError(`Document ${i + 1} is not a mapping`);
    const r = raw as Record<string, unknown>;
    if (r.action) throw new SigmaError("Rule collections (action: global/reset/repeat) are not supported; paste standalone rules");
    if (r.correlation) throw new SigmaError("Correlation rules are not supported");
    const warnings: string[] = [];
    const title = typeof r.title === "string" ? r.title : "";
    if (!title) throw new SigmaError("Missing title");
    const det = r.detection as Record<string, unknown> | undefined;
    if (!det || typeof det !== "object") throw new SigmaError(`${title}: missing detection`);
    const ls = (r.logsource ?? {}) as Record<string, string>;
    if (!r.logsource) warnings.push("Missing logsource");
    const cond = det.condition;
    const conditions = Array.isArray(cond) ? cond : [cond];
    if (!conditions.length || conditions.some((c) => typeof c !== "string")) throw new SigmaError(`${title}: detection.condition must be a string`);
    if (conditions.length > 1) warnings.push("Multiple conditions are OR-ed together");
    const condition = conditions.length > 1 ? conditions.map((c) => `(${c})`).join(" or ") : (conditions[0] as string);
    if (condition.includes("|")) throw new SigmaError(`${title}: aggregation conditions (| count() …) are deprecated and not supported; use a correlation engine`);
    const searches: Record<string, Search> = {};
    for (const [name, value] of Object.entries(det)) {
      if (name === "condition" || name === "timeframe") continue;
      if (Array.isArray(value)) {
        if (value.every((v) => v === null || typeof v !== "object")) searches[name] = { kind: "keywords", values: value as Scalar[], modifiers: [] };
        else if (value.every((v) => v && typeof v === "object" && !Array.isArray(v))) searches[name] = { kind: "or", groups: value.map((v) => parseMatchers(v as Record<string, unknown>)) };
        else throw new SigmaError(`${title}: search '${name}' mixes keywords and field maps`);
      } else if (value && typeof value === "object") {
        const keys = Object.keys(value);
        if (keys.length === 1 && keys[0].startsWith("|")) {
          // keyword list with modifiers: "|all": [...]
          searches[name] = { kind: "keywords", values: toScalars((value as Record<string, unknown>)[keys[0]]), modifiers: keys[0].slice(1).split("|") };
        } else searches[name] = { kind: "and", matchers: parseMatchers(value as Record<string, unknown>) };
      } else if (typeof value === "string" || typeof value === "number") searches[name] = { kind: "keywords", values: [value], modifiers: [] };
      else throw new SigmaError(`${title}: search '${name}' has an unsupported shape`);
    }
    compileCondition(condition, Object.keys(searches));
    const tags = Array.isArray(r.tags) ? r.tags.map(String) : [];
    if (typeof r.level === "string" && !LEVELS.includes(r.level)) warnings.push(`Unknown level '${r.level}'`);
    if (typeof r.status === "string" && !STATUSES.includes(r.status)) warnings.push(`Unknown status '${r.status}'`);
    if (r.id && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(r.id))) warnings.push("id is not a UUID");
    for (const t of tags) if (!/^[a-z0-9_-]+\.[a-z0-9._-]+$/i.test(t)) warnings.push(`Tag '${t}' is not namespace.value`);
    return {
      title,
      id: r.id ? String(r.id) : undefined,
      status: r.status ? String(r.status) : undefined,
      description: r.description ? String(r.description) : undefined,
      author: r.author ? String(r.author) : undefined,
      date: r.date ? String(r.date) : undefined,
      references: Array.isArray(r.references) ? r.references.map(String) : [],
      tags,
      attack: tags.filter((t) => /^attack\.t\d{4}(\.\d{3})?$/i.test(t)).map((t) => t.slice(7).toUpperCase()),
      level: r.level ? String(r.level) : undefined,
      logsource: { product: ls.product, category: ls.category, service: ls.service },
      falsepositives: Array.isArray(r.falsepositives) ? r.falsepositives.map(String) : r.falsepositives ? [String(r.falsepositives)] : [],
      fields: Array.isArray(r.fields) ? r.fields.map(String) : [],
      searches,
      condition,
      warnings,
    };
  });
}

// ───────────────────────────── condition

type Cond = { t: "id"; name: string } | { t: "not"; e: Cond } | { t: "and" | "or"; l: Cond; r: Cond } | { t: "of"; quant: "all" | "one"; pattern: string };

export function compileCondition(src: string, names: string[]): Cond {
  const toks = src.match(/\(|\)|[^\s()]+/g) ?? [];
  let i = 0;
  const peek = () => toks[i]?.toLowerCase();
  const expand = (pattern: string) => (pattern === "them" ? names.filter((n) => !n.startsWith("_")) : names.filter((n) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`).test(n)));
  const parseOr = (): Cond => {
    let l = parseAnd();
    while (peek() === "or") {
      i++;
      l = { t: "or", l, r: parseAnd() };
    }
    return l;
  };
  const parseAnd = (): Cond => {
    let l = parseNot();
    while (peek() === "and") {
      i++;
      l = { t: "and", l, r: parseNot() };
    }
    return l;
  };
  const parseNot = (): Cond => {
    if (peek() === "not") {
      i++;
      return { t: "not", e: parseNot() };
    }
    return parseAtom();
  };
  const parseAtom = (): Cond => {
    const t = toks[i++];
    if (t === undefined) throw new SigmaError("Condition ends unexpectedly");
    if (t === "(") {
      const e = parseOr();
      if (toks[i++] !== ")") throw new SigmaError("Missing ')' in condition");
      return e;
    }
    const lower = t.toLowerCase();
    if (lower === "1" || lower === "all" || lower === "any") {
      if (peek() !== "of") throw new SigmaError(`Expected 'of' after '${t}'`);
      i++;
      const pattern = toks[i++];
      if (!pattern) throw new SigmaError("Expected a search pattern after 'of'");
      if (!expand(pattern).length) throw new SigmaError(`'${pattern}' matches no search identifier`);
      return { t: "of", quant: lower === "all" ? "all" : "one", pattern };
    }
    if (!names.includes(t)) throw new SigmaError(`Unknown search identifier '${t}' in condition`);
    return { t: "id", name: t };
  };
  const cond = parseOr();
  if (i < toks.length) throw new SigmaError(`Unexpected '${toks[i]}' in condition`);
  return cond;
}

// ───────────────────────────── evaluation

export type SigmaEvent = Record<string, unknown>;

const ALIASES: Record<string, string[]> = {
  commandline: ["process.command_line", "process.args"],
  image: ["process.executable"],
  parentimage: ["process.parent.executable"],
  parentcommandline: ["process.parent.command_line"],
  originalfilename: ["process.pe.original_file_name"],
  user: ["user.name"],
  targetfilename: ["file.path"],
  destinationip: ["destination.ip"],
  destinationport: ["destination.port"],
  destinationhostname: ["destination.domain"],
  sourceip: ["source.ip"],
  sourceport: ["source.port"],
  queryname: ["dns.question.name"],
  eventid: ["event.code", "winlog.event_id"],
  processid: ["process.pid"],
  targetobject: ["registry.path"],
  details: ["registry.data.strings"],
  computername: ["host.name", "computer"],
  hashes: ["process.hash.sha256", "file.hash.sha256"],
};

/** Flatten nested objects to dotted keys (lower-cased), and index Windows EventData / winlog.event_data children by their own names. */
export function flattenEvent(ev: SigmaEvent): Map<string, unknown> {
  const out = new Map<string, unknown>();
  const walk = (v: unknown, prefix: string, depth: number) => {
    if (depth > 8) return;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      for (const [k, x] of Object.entries(v)) walk(x, prefix ? `${prefix}.${k}` : k, depth + 1);
    } else {
      out.set(prefix.toLowerCase(), v);
      const last = prefix.split(".").pop()!.toLowerCase();
      const parent = prefix.toLowerCase();
      if (/(eventdata|event_data|userdata|system)\.[^.]+$/.test(parent) && !out.has(last)) out.set(last, v);
    }
  };
  walk(ev, "", 0);
  return out;
}

function lookup(ev: Map<string, unknown>, field: string): unknown {
  const f = field.toLowerCase();
  if (ev.has(f)) return ev.get(f);
  for (const alt of ALIASES[f] ?? []) if (ev.has(alt)) return ev.get(alt);
  return undefined;
}

function wildcardRegex(value: string, cased: boolean): RegExp {
  let re = "";
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === "\\" && (value[i + 1] === "*" || value[i + 1] === "?" || value[i + 1] === "\\")) {
      re += `\\${value[i + 1]}`;
      i++;
    } else if (c === "*") re += "[\\s\\S]*";
    else if (c === "?") re += "[\\s\\S]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`, cased ? "" : "i");
}

function encodeUtf16(s: string, be: boolean): string {
  let out = "";
  for (const c of s) {
    const n = c.charCodeAt(0);
    out += be ? String.fromCharCode(n >> 8, n & 255) : String.fromCharCode(n & 255, n >> 8);
  }
  return out;
}

function b64(s: string): string {
  return btoa(s);
}

function base64OffsetVariants(s: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < 3; i++) {
    const enc = b64("\0".repeat(i) + s);
    const lead = [0, 2, 3][i];
    const rem = (s.length + i) % 3;
    const trail = rem === 0 ? 0 : rem === 1 ? 3 : 2;
    out.push(enc.slice(lead, enc.length - trail));
  }
  return out;
}

/** The literal strings a value expands to under encoding modifiers. */
export function expandValue(value: string, mods: string[]): string[] {
  let variants = [value];
  if (mods.includes("windash")) variants = variants.flatMap((v) => [...new Set(["-", "/", "–", "—", "―"].map((d) => v.replace(/(^|\s)-/g, `$1${d}`)))]);
  if (mods.includes("utf16le") || mods.includes("wide") || mods.includes("utf16")) variants = variants.map((v) => encodeUtf16(v, false));
  else if (mods.includes("utf16be")) variants = variants.map((v) => encodeUtf16(v, true));
  if (mods.includes("base64")) variants = variants.map(b64);
  if (mods.includes("base64offset")) variants = variants.flatMap(base64OffsetVariants);
  return variants;
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr ?? 32);
  const toNum = (a: string) => {
    const p = a.split(".").map(Number);
    return p.length === 4 && p.every((x) => x >= 0 && x <= 255) ? ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0 : null;
  };
  const a = toNum(ip);
  const b = toNum(base);
  if (a === null || b === null || !(bits >= 0 && bits <= 32)) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

export interface MatchEvidence {
  search: string;
  field: string | null;
  value: string;
  pattern: string;
}

function matchValue(actual: unknown, m: Matcher, ev: Map<string, unknown>): { ok: boolean; evidence?: MatchEvidence[] } {
  const mods = m.modifiers;
  const cased = mods.includes("cased");
  if (mods.includes("exists")) {
    const want = m.values[0] === true || m.values[0] === "true";
    return { ok: (actual !== undefined && actual !== null) === want };
  }
  const actualList = Array.isArray(actual) ? actual : [actual];
  const test = (v: Scalar): { ok: boolean; pattern: string; hit?: string } => {
    if (v === null) return { ok: actualList.every((a) => a === undefined || a === null || a === ""), pattern: "null" };
    for (const a of actualList) {
      if (a === undefined || a === null) continue;
      const s = typeof a === "object" ? JSON.stringify(a) : String(a);
      if (mods.includes("fieldref")) {
        const other = lookup(ev, String(v));
        if (other !== undefined && String(other) === s) return { ok: true, pattern: `= ${v}`, hit: s };
        continue;
      }
      if (mods.some((x) => ["lt", "lte", "gt", "gte"].includes(x))) {
        const n = Number(s);
        const t = Number(v);
        if (Number.isNaN(n) || Number.isNaN(t)) continue;
        const ok = mods.includes("lt") ? n < t : mods.includes("lte") ? n <= t : mods.includes("gt") ? n > t : n >= t;
        if (ok) return { ok, pattern: `${mods.find((x) => ["lt", "lte", "gt", "gte"].includes(x))} ${v}`, hit: s };
        continue;
      }
      if (mods.includes("cidr")) {
        if (ipInCidr(s, String(v))) return { ok: true, pattern: `in ${v}`, hit: s };
        continue;
      }
      if (mods.includes("re")) {
        let re: RegExp;
        try {
          re = new RegExp(String(v), `${mods.includes("i") ? "i" : ""}${mods.includes("m") ? "m" : ""}${mods.includes("s") ? "s" : ""}`);
        } catch {
          throw new SigmaError(`Invalid regular expression: ${v}`);
        }
        if (re.test(s)) return { ok: true, pattern: `/${v}/`, hit: s };
        continue;
      }
      if (typeof v === "boolean" || typeof v === "number") {
        if (s.toLowerCase() === String(v).toLowerCase()) return { ok: true, pattern: String(v), hit: s };
        continue;
      }
      for (const lit of expandValue(v, mods)) {
        const pat = mods.includes("contains") ? `*${lit}*` : mods.includes("startswith") ? `${lit}*` : mods.includes("endswith") ? `*${lit}` : lit;
        // Encoded variants are literal; only the original value may carry wildcards.
        const re = lit === v ? wildcardRegex(pat, cased) : wildcardRegex(pat.replace(/\\/g, "\\\\"), cased);
        if (re.test(s)) return { ok: true, pattern: pat, hit: s };
      }
    }
    return { ok: false, pattern: String(v) };
  };
  const results = m.values.map(test);
  const ok = mods.includes("all") ? results.every((r) => r.ok) : results.some((r) => r.ok);
  return { ok, evidence: ok ? results.filter((r) => r.ok).map((r) => ({ search: "", field: m.field, value: r.hit ?? "", pattern: r.pattern })) : undefined };
}

function evalSearch(name: string, s: Search, ev: Map<string, unknown>, raw: string): { ok: boolean; evidence: MatchEvidence[] } {
  const evidence: MatchEvidence[] = [];
  const runAnd = (ms: Matcher[]) => {
    const local: MatchEvidence[] = [];
    for (const m of ms) {
      const actual = m.field === null ? raw : lookup(ev, m.field);
      const r = matchValue(actual, m, ev);
      if (!r.ok) return false;
      if (r.evidence) local.push(...r.evidence.map((e) => ({ ...e, search: name })));
    }
    evidence.push(...local);
    return true;
  };
  if (s.kind === "and") return { ok: runAnd(s.matchers), evidence };
  if (s.kind === "or") return { ok: s.groups.some((g) => runAnd(g)), evidence };
  const kw = { field: null, modifiers: ["contains", ...s.modifiers.filter((m) => m !== "contains")], values: s.values } satisfies Matcher;
  const r = matchValue(raw, kw, ev);
  return { ok: r.ok, evidence: (r.evidence ?? []).map((e) => ({ ...e, search: name, value: e.value.slice(0, 200) })) };
}

export interface SigmaMatch {
  index: number;
  evidence: MatchEvidence[];
}

export function evaluateSigma(rule: SigmaRule, events: SigmaEvent[]): SigmaMatch[] {
  const names = Object.keys(rule.searches);
  const cond = compileCondition(rule.condition, names);
  const out: SigmaMatch[] = [];
  events.forEach((event, index) => {
    const flat = flattenEvent(event);
    const raw = JSON.stringify(event);
    const cache = new Map<string, { ok: boolean; evidence: MatchEvidence[] }>();
    const search = (n: string) => {
      let r = cache.get(n);
      if (!r) {
        r = evalSearch(n, rule.searches[n], flat, raw);
        cache.set(n, r);
      }
      return r;
    };
    const used = new Set<string>();
    const ev = (c: Cond): boolean => {
      switch (c.t) {
        case "id": {
          const r = search(c.name).ok;
          if (r) used.add(c.name);
          return r;
        }
        case "not":
          return !ev(c.e);
        case "and":
          return ev(c.l) && ev(c.r);
        case "or":
          return ev(c.l) || ev(c.r);
        case "of": {
          const targets = c.pattern === "them" ? names.filter((n) => !n.startsWith("_")) : names.filter((n) => new RegExp(`^${c.pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`).test(n));
          const hits = targets.filter((n) => search(n).ok);
          hits.forEach((h) => used.add(h));
          return c.quant === "all" ? hits.length === targets.length : hits.length > 0;
        }
      }
    };
    if (ev(cond)) out.push({ index, evidence: [...used].flatMap((n) => cache.get(n)?.evidence ?? []) });
  });
  return out;
}

// ───────────────────────────── event input

/** Parse events from JSON (array or object), NDJSON, CSV with a header row, or Windows Event XML. */
export function parseEvents(text: string): { events: SigmaEvent[]; format: string } {
  const t = text.trim();
  if (!t) return { events: [], format: "empty" };
  if (t.startsWith("<")) {
    const events: SigmaEvent[] = [];
    for (const m of t.matchAll(/<Event[\s>][\s\S]*?<\/Event>/g)) {
      const x = m[0];
      const ev: SigmaEvent = {};
      const sys = (tag: string) => new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`).exec(x)?.[1];
      ev.EventID = Number(sys("EventID") ?? NaN);
      ev.Channel = sys("Channel");
      ev.Computer = sys("Computer");
      ev.Provider_Name = /<Provider[^>]*Name=['"]([^'"]+)/.exec(x)?.[1];
      ev.TimeCreated = /<TimeCreated[^>]*SystemTime=['"]([^'"]+)/.exec(x)?.[1];
      for (const d of x.matchAll(/<Data Name=['"]([^'"]+)['"]\s*(?:\/>|>([\s\S]*?)<\/Data>)/g)) ev[d[1]] = decodeXml(d[2] ?? "");
      events.push(ev);
      if (events.length >= 100_000) break;
    }
    return { events, format: "Windows Event XML" };
  }
  if (t.startsWith("[")) {
    const v = JSON.parse(t);
    if (!Array.isArray(v)) throw new SigmaError("Expected a JSON array of events");
    return { events: v.filter((e) => e && typeof e === "object"), format: "JSON array" };
  }
  if (t.startsWith("{")) {
    const lines = t.split(/\r?\n/).filter((l) => l.trim());
    try {
      if (lines.length > 1) return { events: lines.map((l) => JSON.parse(l)), format: "NDJSON" };
    } catch {
      // fall through to single object
    }
    const v = JSON.parse(t);
    return { events: Array.isArray(v) ? v : [v], format: "JSON object" };
  }
  const rows = parseCsv(t);
  if (rows.length < 2) throw new SigmaError("Could not recognise the event format (JSON, NDJSON, CSV or Windows Event XML)");
  const header = rows[0];
  return { events: rows.slice(1).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""]))), format: "CSV" };
}

function decodeXml(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_m, n) => String.fromCharCode(Number(n))).replace(/&amp;/g, "&");
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') q = false;
      else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") {
      row.push(cell);
      cell = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else cell += c;
  }
  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

// ───────────────────────────── conversion

export type Backend = "splunk" | "kql" | "lucene";
export const BACKENDS: { id: Backend; label: string }[] = [
  { id: "splunk", label: "Splunk SPL" },
  { id: "kql", label: "Microsoft KQL" },
  { id: "lucene", label: "Elastic Lucene" },
];

export function convertSigma(rule: SigmaRule, backend: Backend): { query: string; warnings: string[] } {
  const warnings: string[] = [];
  const names = Object.keys(rule.searches);
  const cond = compileCondition(rule.condition, names);

  const quote = (s: string) => (backend === "lucene" ? s.replace(/([+\-=&|><!(){}[\]^"~?:\\/ ])/g, "\\$1") : `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`);
  const fieldExpr = (m: Matcher, v: Scalar): string => {
    const f = m.field;
    const mods = m.modifiers;
    if (mods.includes("fieldref")) {
      warnings.push("fieldref is not portable; written as a comment");
      return backend === "kql" ? `${f} == ${v}` : `/* ${f} equals field ${v} */`;
    }
    if (v === null) return backend === "kql" ? `isempty(${f})` : backend === "splunk" ? `NOT ${f}=*` : `NOT _exists_:${f}`;
    if (mods.includes("exists")) {
      const want = v === true || v === "true";
      return backend === "kql" ? `${want ? "isnotempty" : "isempty"}(${f})` : backend === "splunk" ? `${want ? "" : "NOT "}${f}=*` : `${want ? "" : "NOT "}_exists_:${f}`;
    }
    const cmp = mods.find((x) => ["lt", "lte", "gt", "gte"].includes(x));
    if (cmp) {
      const op = { lt: "<", lte: "<=", gt: ">", gte: ">=" }[cmp];
      return backend === "lucene" ? `${f}:${cmp.startsWith("l") ? `[* TO ${v}${cmp === "lt" ? "}" : "]"}` : `${cmp === "gt" ? "{" : "["}${v} TO *]`}` : `${f}${op}${v}`;
    }
    if (mods.includes("cidr")) {
      if (backend === "kql") return `ipv4_is_in_range(${f}, "${v}")`;
      if (backend === "splunk") return `${f}="${v}"`;
      return `${f}:${quote(String(v))}`;
    }
    if (mods.includes("re")) {
      if (backend === "kql") return `${f} matches regex @"${String(v).replace(/"/g, '""')}"`;
      if (backend === "lucene") return `${f}:/${String(v).replace(/\//g, "\\/")}/`;
      throw new SigmaError("This rule uses a regular expression (|re). Splunk search syntax cannot express it inline; use the KQL or Lucene output, or add a | regex command yourself.");
    }
    const lits = typeof v === "string" ? expandValue(v, mods) : [String(v)];
    const parts = lits.map((lit) => {
      const kind = mods.includes("contains") ? "contains" : mods.includes("startswith") ? "startswith" : mods.includes("endswith") ? "endswith" : lit.includes("*") ? "wildcard" : "eq";
      if (backend === "kql") {
        const q = quote(lit.replace(/\*/g, ""));
        const cs = mods.includes("cased") ? "_cs" : "";
        if (kind === "wildcard") return `${f} matches regex @"(?i)^${lit.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$"`;
        return kind === "eq" ? `${f} ${mods.includes("cased") ? "==" : "=~"} ${q}` : `${f} ${kind}${cs} ${q}`;
      }
      const pat = kind === "contains" ? `*${lit}*` : kind === "startswith" ? `${lit}*` : kind === "endswith" ? `*${lit}` : lit;
      if (backend === "splunk") return f ? `${f}=${quote(pat)}` : quote(pat);
      const escaped = pat.split("*").map((x) => quote(x)).join("*");
      return f ? `${f}:${escaped}` : escaped;
    });
    return parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0];
  };
  const join = (items: string[], op: "AND" | "OR") => {
    const o = backend === "kql" ? op.toLowerCase() : op;
    return items.length > 1 ? `(${items.join(` ${o} `)})` : items[0] ?? "";
  };
  const matcherExpr = (m: Matcher): string => {
    if (m.field === null) return join(m.values.map((v) => fieldExpr({ ...m, field: backend === "kql" ? "*" : null, modifiers: ["contains"] }, v)), "OR");
    return join(m.values.map((v) => fieldExpr(m, v)), m.modifiers.includes("all") ? "AND" : "OR");
  };
  const searchExpr = (name: string): string => {
    const s = rule.searches[name];
    if (s.kind === "and") return join(s.matchers.map(matcherExpr), "AND");
    if (s.kind === "or") return join(s.groups.map((g) => join(g.map(matcherExpr), "AND")), "OR");
    if (backend === "kql") return join(s.values.map((v) => `* contains ${quote(String(v))}`), s.modifiers.includes("all") ? "AND" : "OR");
    return join(s.values.map((v) => quote(backend === "splunk" ? `*${v}*` : String(v))), s.modifiers.includes("all") ? "AND" : "OR");
  };
  const condExpr = (c: Cond): string => {
    switch (c.t) {
      case "id":
        return searchExpr(c.name);
      case "not":
        return backend === "kql" ? `not(${condExpr(c.e)})` : `NOT ${condExpr(c.e)}`;
      case "and":
        return join([condExpr(c.l), condExpr(c.r)], "AND");
      case "or":
        return join([condExpr(c.l), condExpr(c.r)], "OR");
      case "of": {
        const targets = c.pattern === "them" ? names.filter((n) => !n.startsWith("_")) : names.filter((n) => new RegExp(`^${c.pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`).test(n));
        return join(targets.map(searchExpr), c.quant === "all" ? "AND" : "OR");
      }
    }
  };
  const body = condExpr(cond);
  const ls = [rule.logsource.product, rule.logsource.category, rule.logsource.service].filter(Boolean).join("/");
  if (backend === "kql") return { query: `// ${rule.title}${ls ? ` (logsource: ${ls})` : ""}\n// Field names are Sigma's; map them to your table schema.\n<Table>\n| where ${body}`, warnings };
  if (backend === "splunk") return { query: `${body}\n\`\`\` ${rule.title}${ls ? ` — logsource ${ls}` : ""}; add your index/sourcetype \`\`\``, warnings };
  return { query: body, warnings };
}
