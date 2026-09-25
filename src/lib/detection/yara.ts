import { latin1 } from "@/lib/analysis/bytes";
import { entropy } from "@/lib/analysis/bytes";
import { md5, sha256Sync } from "@/lib/analysis/hash";
import type { PeAnalysis } from "@/lib/analysis/pe";

// A YARA engine for the rule language's common core. Rules are compiled to a
// tree and evaluated against bytes in the browser. Anything outside the
// supported subset is a compile error that names the feature — a rule is
// never half-evaluated and reported as a match.

export class YaraError extends Error {
  constructor(
    message: string,
    readonly line: number,
    readonly column: number
  ) {
    super(message);
    this.name = "YaraError";
  }
}

// ───────────────────────────── lexer

type TokKind = "id" | "str" | "num" | "hexstr" | "regex" | "op" | "strid" | "strcount" | "stroffset" | "strlen" | "eof";
interface Tok {
  kind: TokKind;
  value: string;
  num?: number;
  flags?: string;
  line: number;
  col: number;
}

const KEYWORDS = new Set(["rule", "private", "global", "meta", "strings", "condition", "import", "include", "and", "or", "not", "at", "in", "of", "them", "all", "any", "none", "for", "true", "false", "filesize", "entrypoint", "contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals", "matches", "defined"]);

function lex(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  let line = 1;
  let lineStart = 0;
  const err = (m: string, at = i) => new YaraError(m, line, at - lineStart + 1);
  const push = (kind: TokKind, value: string, start: number, extra: Partial<Tok> = {}) => toks.push({ kind, value, line, col: start - lineStart + 1, ...extra });
  let expectPattern = false; // after `$x =` a hex string or regex may follow

  while (i < src.length) {
    const c = src[i];
    if (c === "\n") {
      line++;
      lineStart = ++i;
      continue;
    }
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (src.startsWith("//", i)) {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (src.startsWith("/*", i)) {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) throw err("Unterminated comment");
      for (let k = i; k < end; k++) if (src[k] === "\n") {
        line++;
        lineStart = k + 1;
      }
      i = end + 2;
      continue;
    }
    const start = i;
    if (expectPattern && c === "{") {
      const end = src.indexOf("}", i);
      if (end < 0) throw err("Unterminated hex string");
      const body = src.slice(i + 1, end);
      push("hexstr", body, start);
      for (const ch of body) if (ch === "\n") line++;
      i = end + 1;
      expectPattern = false;
      continue;
    }
    const prev = toks[toks.length - 1];
    const regexAllowed = expectPattern || (prev && prev.kind === "id" && prev.value === "matches");
    if (c === "/" && regexAllowed) {
      let j = i + 1;
      let body = "";
      while (j < src.length && src[j] !== "/") {
        if (src[j] === "\\" && j + 1 < src.length) {
          body += src[j] + src[j + 1];
          j += 2;
        } else if (src[j] === "\n") throw err("Unterminated regular expression");
        else body += src[j++];
      }
      if (j >= src.length) throw err("Unterminated regular expression");
      j++;
      let flags = "";
      while (j < src.length && /[is]/.test(src[j])) flags += src[j++];
      push("regex", body, start, { flags });
      i = j;
      expectPattern = false;
      continue;
    }
    expectPattern = false;
    if (c === '"') {
      let j = i + 1;
      let s = "";
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\n") throw err("Unterminated string");
        if (src[j] === "\\") {
          const n = src[j + 1];
          if (n === "n") s += "\n";
          else if (n === "t") s += "\t";
          else if (n === "r") s += "\r";
          else if (n === "\\") s += "\\";
          else if (n === '"') s += '"';
          else if (n === "x") {
            const h = src.slice(j + 2, j + 4);
            if (!/^[0-9a-fA-F]{2}$/.test(h)) throw err("Invalid \\x escape", j);
            s += String.fromCharCode(parseInt(h, 16));
            j += 2;
          } else throw err(`Unknown escape \\${n}`, j);
          j += 2;
        } else s += src[j++];
      }
      if (j >= src.length) throw err("Unterminated string");
      push("str", s, start);
      i = j + 1;
      continue;
    }
    if (c === "$" || c === "#" || c === "@" || (c === "!" && /[A-Za-z_]/.test(src[i + 1] ?? ""))) {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_*]/.test(src[j])) j++;
      const name = src.slice(i + 1, j);
      const kind: TokKind = c === "$" ? "strid" : c === "#" ? "strcount" : c === "@" ? "stroffset" : "strlen";
      push(kind, name, start);
      i = j;
      // `$a = ` introduces a pattern
      let k = j;
      while (k < src.length && (src[k] === " " || src[k] === "\t")) k++;
      if (c === "$" && src[k] === "=" && src[k + 1] !== "=") {
        push("op", "=", k);
        i = k + 1;
        expectPattern = true;
      }
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      let n: number;
      if (src.startsWith("0x", i) || src.startsWith("0X", i)) {
        j = i + 2;
        while (/[0-9a-fA-F]/.test(src[j] ?? "")) j++;
        n = parseInt(src.slice(i + 2, j), 16);
      } else if (src.startsWith("0o", i)) {
        j = i + 2;
        while (/[0-7]/.test(src[j] ?? "")) j++;
        n = parseInt(src.slice(i + 2, j), 8);
      } else {
        while (/[0-9.]/.test(src[j] ?? "") && !(src[j] === "." && src[j + 1] === ".")) j++;
        n = Number(src.slice(i, j));
      }
      if (src.startsWith("KB", j)) {
        n *= 1024;
        j += 2;
      } else if (src.startsWith("MB", j)) {
        n *= 1024 * 1024;
        j += 2;
      }
      if (!Number.isFinite(n)) throw err("Invalid number");
      push("num", src.slice(i, j), start, { num: n });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (/[A-Za-z0-9_]/.test(src[j] ?? "")) j++;
      push("id", src.slice(i, j), start);
      i = j;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (["..", "==", "!=", "<=", ">=", "<<", ">>"].includes(two)) {
      push("op", two, start);
      i += 2;
      continue;
    }
    if ("(){}[]:,=<>+-*\\%&|^~.".includes(c)) {
      push("op", c, start);
      i++;
      continue;
    }
    throw err(`Unexpected character '${c}'`);
  }
  toks.push({ kind: "eof", value: "", line, col: i - lineStart + 1 });
  return toks;
}

// ───────────────────────────── AST

export interface YaraString {
  id: string;
  kind: "text" | "hex" | "regex";
  source: string;
  modifiers: string[];
  regex: RegExp;
  fullword: boolean;
  isPrivate: boolean;
  line: number;
}

type Expr =
  | { t: "bool"; v: boolean }
  | { t: "num"; v: number }
  | { t: "str"; v: string }
  | { t: "regex"; re: RegExp }
  | { t: "filesize" }
  | { t: "entrypoint" }
  | { t: "not"; e: Expr }
  | { t: "and" | "or"; l: Expr; r: Expr }
  | { t: "bin"; op: string; l: Expr; r: Expr }
  | { t: "neg" | "bitnot"; e: Expr }
  | { t: "strmatch"; id: string; at?: Expr; range?: [Expr, Expr] }
  | { t: "strcount"; id: string; range?: [Expr, Expr] }
  | { t: "stroffset" | "strlen"; id: string; index: Expr }
  | { t: "of"; quant: Quant; set: string[] | "them"; range?: [Expr, Expr]; ruleSet?: string[] }
  | { t: "forof"; quant: Quant; set: string[] | "them"; body: Expr }
  | { t: "forin"; quant: Quant; vars: string[]; iter: { range: [Expr, Expr] } | { list: Expr[] }; body: Expr }
  | { t: "ident"; path: (string | { index: Expr } | { call: Expr[] })[]; line: number; col: number };

type Quant = { kind: "all" | "any" | "none" } | { kind: "num"; e: Expr } | { kind: "pct"; e: Expr };

export interface YaraRule {
  name: string;
  tags: string[];
  meta: Record<string, string | number | boolean>;
  strings: YaraString[];
  condition: Expr;
  isPrivate: boolean;
  isGlobal: boolean;
  line: number;
}

export interface CompiledRules {
  imports: string[];
  rules: YaraRule[];
}

const SUPPORTED_MODULES = new Set(["pe", "math", "hash"]);

function escapeByte(b: number): string {
  return `\\x${b.toString(16).padStart(2, "0")}`;
}

function base64Variants(s: string, wide: boolean): string[] {
  const out: string[] = [];
  const bytes = wide ? [...s].flatMap((c) => [c.charCodeAt(0) & 0xff, 0]) : [...s].map((c) => c.charCodeAt(0) & 0xff);
  for (let i = 0; i < 3; i++) {
    const padded = [...new Array(i).fill(0), ...bytes];
    const b64 = btoa(String.fromCharCode(...padded));
    const lead = [0, 2, 3][i];
    const rem = padded.length % 3;
    const trail = rem === 0 ? 0 : rem === 1 ? 3 : 2;
    out.push(b64.slice(lead, b64.length - trail));
  }
  return out;
}

function compileHex(body: string, line: number): string {
  const s = body.replace(/\/\/[^\n]*/g, "").replace(/\s+/g, "");
  let i = 0;
  const parseSeq = (stopAt: string[]): string => {
    let out = "";
    let bytes = 0;
    while (i < s.length && !stopAt.includes(s[i])) {
      const c = s[i];
      if (c === "[") {
        const end = s.indexOf("]", i);
        if (end < 0) throw new YaraError("Unterminated jump in hex string", line, 1);
        const spec = s.slice(i + 1, end);
        const m = /^(\d*)(-(\d*))?$/.exec(spec);
        if (!m) throw new YaraError(`Invalid jump [${spec}]`, line, 1);
        const lo = m[1] ? Number(m[1]) : 0;
        const hi = m[2] ? (m[3] ? Number(m[3]) : "") : lo;
        if (hi !== "" && hi < lo) throw new YaraError(`Invalid jump [${spec}]`, line, 1);
        out += `[\\s\\S]{${lo},${hi}}?`;
        i = end + 1;
      } else if (c === "(") {
        i++;
        const alts: string[] = [];
        for (;;) {
          alts.push(parseSeq(["|", ")"]));
          if (s[i] === "|") i++;
          else if (s[i] === ")") {
            i++;
            break;
          } else throw new YaraError("Unterminated alternative in hex string", line, 1);
        }
        out += `(?:${alts.join("|")})`;
      } else if (c === "~") {
        const pair = s.slice(i + 1, i + 3);
        if (!/^[0-9a-fA-F]{2}$/.test(pair)) throw new YaraError("~ must precede a full byte", line, 1);
        out += `[^${escapeByte(parseInt(pair, 16))}]`;
        i += 3;
        bytes++;
      } else {
        const pair = s.slice(i, i + 2);
        if (!/^[0-9a-fA-F?]{2}$/.test(pair)) throw new YaraError(`Invalid hex token '${pair}'`, line, 1);
        if (pair === "??") out += "[\\s\\S]";
        else if (pair[0] === "?") {
          const lo = parseInt(pair[1], 16);
          out += `[${Array.from({ length: 16 }, (_, h) => escapeByte((h << 4) | lo)).join("")}]`;
        } else if (pair[1] === "?") {
          const hi = parseInt(pair[0], 16);
          out += `[${escapeByte(hi << 4)}-${escapeByte((hi << 4) | 0xf)}]`;
        } else out += escapeByte(parseInt(pair, 16));
        i += 2;
        bytes++;
      }
    }
    void bytes;
    return out;
  };
  const re = parseSeq([]);
  if (!re) throw new YaraError("Empty hex string", line, 1);
  return re;
}

function textToPattern(text: string, mods: Set<string>, xorRange: [number, number] | null): string {
  const enc = (bytes: number[]) => bytes.map(escapeByte).join("");
  const raw = [...text].map((c) => c.charCodeAt(0) & 0xff);
  const variants: number[][] = [];
  const ascii = mods.has("ascii") || !mods.has("wide");
  if (ascii) variants.push(raw);
  if (mods.has("wide")) variants.push(raw.flatMap((b) => [b, 0]));
  if (xorRange) {
    const out: string[] = [];
    for (const v of variants) for (let k = xorRange[0]; k <= xorRange[1]; k++) out.push(enc(v.map((b) => b ^ k)));
    return `(?:${[...new Set(out)].join("|")})`;
  }
  if (mods.has("base64") || mods.has("base64wide")) {
    const out: string[] = [];
    for (const v of base64Variants(text, false)) {
      const bytes = [...v].map((c) => c.charCodeAt(0));
      if (mods.has("base64")) out.push(enc(bytes));
      if (mods.has("base64wide")) out.push(enc(bytes.flatMap((b) => [b, 0])));
    }
    return `(?:${out.join("|")})`;
  }
  return variants.length === 1 ? enc(variants[0]) : `(?:${variants.map(enc).join("|")})`;
}

// ───────────────────────────── parser

export function compileYara(src: string): CompiledRules {
  const toks = lex(src);
  let p = 0;
  const peek = (o = 0) => toks[p + o];
  const next = () => toks[p++];
  const fail = (m: string, t = peek()) => new YaraError(m, t.line, t.col);
  const isOp = (v: string) => peek().kind === "op" && peek().value === v;
  const isId = (v: string) => peek().kind === "id" && peek().value === v;
  const expectOp = (v: string) => {
    if (!isOp(v)) throw fail(`Expected '${v}' but found '${peek().value || "end of input"}'`);
    return next();
  };
  const expectId = (v?: string) => {
    if (peek().kind !== "id" || (v && peek().value !== v)) throw fail(v ? `Expected '${v}'` : `Expected an identifier, found '${peek().value || "end of input"}'`);
    return next();
  };

  const imports: string[] = [];
  const rules: YaraRule[] = [];
  const ruleNames = new Set<string>();

  while (peek().kind !== "eof") {
    if (isId("import")) {
      next();
      const m = next();
      if (m.kind !== "str") throw fail("import needs a module name in quotes", m);
      if (!SUPPORTED_MODULES.has(m.value)) throw new YaraError(`Module "${m.value}" is not supported by this engine (supported: pe, math, hash)`, m.line, m.col);
      imports.push(m.value);
      continue;
    }
    if (isId("include")) throw fail("include is not supported: paste the included rules into the editor");
    let isPrivate = false;
    let isGlobal = false;
    while (isId("private") || isId("global")) {
      if (next().value === "private") isPrivate = true;
      else isGlobal = true;
    }
    const ruleTok = expectId("rule");
    const name = expectId().value;
    if (KEYWORDS.has(name)) throw fail(`'${name}' is a reserved word`, toks[p - 1]);
    if (ruleNames.has(name)) throw fail(`Duplicate rule name '${name}'`, toks[p - 1]);
    const tags: string[] = [];
    if (isOp(":")) {
      next();
      while (peek().kind === "id" && !isOp("{")) tags.push(next().value);
    }
    expectOp("{");
    const meta: YaraRule["meta"] = {};
    const strings: YaraString[] = [];
    let condition: Expr | null = null;

    while (!isOp("}")) {
      const section = expectId();
      expectOp(":");
      if (section.value === "meta") {
        while (peek().kind === "id" && peek(1).kind === "op" && peek(1).value === "=") {
          const key = next().value;
          next();
          const v = next();
          if (v.kind === "str") meta[key] = v.value;
          else if (v.kind === "num") meta[key] = v.num!;
          else if (v.kind === "op" && v.value === "-" && peek().kind === "num") meta[key] = -next().num!;
          else if (v.kind === "id" && (v.value === "true" || v.value === "false")) meta[key] = v.value === "true";
          else throw fail("Meta values must be strings, numbers or booleans", v);
        }
      } else if (section.value === "strings") {
        while (peek().kind === "strid") {
          const idTok = next();
          expectOp("=");
          const val = next();
          const mods: string[] = [];
          let xorRange: [number, number] | null = null;
          while (peek().kind === "id" && ["nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide"].includes(peek().value)) {
            const m = next().value;
            mods.push(m);
            if (m === "xor") {
              xorRange = [0, 255];
              if (isOp("(")) {
                next();
                const a = next();
                if (a.kind !== "num") throw fail("xor range needs numbers", a);
                let b = a;
                if (isOp("-")) {
                  next();
                  b = next();
                  if (b.kind !== "num") throw fail("xor range needs numbers", b);
                }
                expectOp(")");
                xorRange = [a.num!, b.num!];
                if (xorRange[0] < 0 || xorRange[1] > 255 || xorRange[0] > xorRange[1]) throw fail("xor range must be within 0-255", a);
              }
            }
            if ((m === "base64" || m === "base64wide") && isOp("(")) throw fail("Custom base64 alphabets are not supported");
          }
          if (peek().kind === "id" && !["condition", "meta", "strings"].includes(peek().value)) throw fail(`Unsupported string modifier '${peek().value}'`);
          const modSet = new Set(mods);
          let pattern: string;
          let kind: YaraString["kind"];
          let flags = "";
          if (val.kind === "str") {
            kind = "text";
            if (!val.value.length) throw fail("Empty string", val);
            pattern = textToPattern(val.value, modSet, xorRange);
            if (modSet.has("nocase")) flags += "i";
            if (xorRange && modSet.has("nocase")) throw fail("xor cannot be combined with nocase", val);
          } else if (val.kind === "hexstr") {
            kind = "hex";
            if (mods.some((m) => m !== "private")) throw fail("Hex strings accept only the private modifier", val);
            pattern = compileHex(val.value, val.line);
          } else if (val.kind === "regex") {
            kind = "regex";
            pattern = val.value;
            if (val.flags?.includes("i") || modSet.has("nocase")) flags += "i";
            if (val.flags?.includes("s")) flags += "s";
            if (modSet.has("wide")) throw fail("wide regular expressions are not supported by this engine", val);
          } else throw fail("Expected a text string, hex string or regular expression", val);
          let regex: RegExp;
          try {
            regex = new RegExp(pattern, `g${flags}`);
          } catch (e) {
            throw new YaraError(`Invalid pattern for $${idTok.value}: ${(e as Error).message}`, val.line, val.col);
          }
          if (idTok.value && strings.some((s) => s.id === idTok.value)) throw fail(`Duplicate string identifier $${idTok.value}`, idTok);
          strings.push({ id: idTok.value || `~anon${strings.length}`, kind, source: val.kind === "hexstr" ? `{ ${val.value.trim().replace(/\s+/g, " ")} }` : val.kind === "regex" ? `/${val.value}/${val.flags}` : JSON.stringify(val.value), modifiers: mods, regex, fullword: modSet.has("fullword"), isPrivate: modSet.has("private"), line: idTok.line });
        }
      } else if (section.value === "condition") {
        condition = parseExpr();
      } else throw fail(`Unknown section '${section.value}'`, section);
    }
    expectOp("}");
    if (!condition) throw new YaraError(`Rule '${name}' has no condition`, ruleTok.line, ruleTok.col);
    validate(condition, strings, name, ruleTok.line);
    rules.push({ name, tags, meta, strings, condition, isPrivate, isGlobal, line: ruleTok.line });
    ruleNames.add(name);
  }
  return { imports, rules };

  function validate(e: Expr, strings: YaraString[], rule: string, line: number) {
    const known = (id: string) => (id.endsWith("*") ? strings.some((s) => s.id.startsWith(id.slice(0, -1))) : strings.some((s) => s.id === id));
    const referenced = new Set<string>();
    const refer = (set: string[] | "them") => {
      for (const s of strings) if (set === "them" || set.some((id) => (id.endsWith("*") ? s.id.startsWith(id.slice(0, -1)) : s.id === id))) referenced.add(s.id);
    };
    const walk = (x: Expr, inFor: boolean) => {
      switch (x.t) {
        case "strmatch":
        case "strcount":
        case "stroffset":
        case "strlen":
          if (x.id === "" && !inFor) throw new YaraError(`Anonymous $ used outside a "for … of" loop in rule '${rule}'`, line, 1);
          if (x.id !== "" && !known(x.id)) throw new YaraError(`Undefined string $${x.id} in rule '${rule}'`, line, 1);
          if (x.id !== "") referenced.add(x.id);
          if (x.t === "strmatch") {
            if (x.at) walk(x.at, inFor);
            if (x.range) x.range.forEach((r) => walk(r, inFor));
          }
          if (x.t === "strcount" && x.range) x.range.forEach((r) => walk(r, inFor));
          if (x.t === "stroffset" || x.t === "strlen") walk(x.index, inFor);
          break;
        case "of":
        case "forof":
          if (x.set !== "them" && !(x.t === "of" && x.ruleSet)) for (const id of x.set) if (!known(id)) throw new YaraError(`Undefined string $${id} in rule '${rule}'`, line, 1);
          if (x.t === "of" && x.ruleSet) {
            for (const r of x.ruleSet) if (!ruleNames.has(r.slice(5))) throw new YaraError(`Rule '${r.slice(5)}' is not defined before '${rule}'`, line, 1);
          } else refer(x.set);
          if (x.t === "forof") walk(x.body, true);
          if (x.t === "of" && x.range) x.range.forEach((r) => walk(r, inFor));
          break;
        case "forin":
          walk(x.body, inFor);
          break;
        case "not":
        case "neg":
        case "bitnot":
          walk(x.e, inFor);
          break;
        case "and":
        case "or":
        case "bin":
          walk(x.l, inFor);
          walk(x.r, inFor);
          break;
        case "ident": {
          const head = x.path[0] as string;
          if (SUPPORTED_MODULES.has(head) && !imports.includes(head)) throw new YaraError(`Module "${head}" is used but not imported (add: import "${head}")`, x.line, x.col);
          if (x.path.length === 1 && !SUPPORTED_MODULES.has(head) && !ruleNames.has(head) && !/^u?int(8|16|32)(be)?$/.test(head)) {
            // Loop variables are resolved at run time; anything else is unknown.
            if (!loopVars.has(head)) throw new YaraError(`Unknown identifier '${head}' (rules can reference only rules defined above them)`, x.line, x.col);
          }
          for (const part of x.path.slice(1)) if (typeof part !== "string") ("index" in part ? [part.index] : part.call).forEach((a) => walk(a, inFor));
          break;
        }
      }
    };
    const loopVars = new Set<string>();
    const collectVars = (x: Expr) => {
      if (x.t === "forin") x.vars.forEach((v) => loopVars.add(v));
      for (const v of Object.values(x)) if (v && typeof v === "object" && "t" in v) collectVars(v as Expr);
    };
    collectVars(e);
    walk(e, false);
    const unused = strings.filter((s) => !referenced.has(s.id));
    if (unused.length) throw new YaraError(`Rule '${rule}': string ${unused[0].id.startsWith("~") ? "$" : `$${unused[0].id}`} is never used in the condition`, unused[0].line, 1);
  }

  // expression parsing
  function parseExpr(): Expr {
    return parseOr();
  }
  function parseOr(): Expr {
    let l = parseAnd();
    while (isId("or")) {
      next();
      l = { t: "or", l, r: parseAnd() };
    }
    return l;
  }
  function parseAnd(): Expr {
    let l = parseNot();
    while (isId("and")) {
      next();
      l = { t: "and", l, r: parseNot() };
    }
    return l;
  }
  function parseNot(): Expr {
    if (isId("not")) {
      next();
      return { t: "not", e: parseNot() };
    }
    if (isId("defined")) throw fail("'defined' is not supported by this engine");
    return parseCmp();
  }
  function parseCmp(): Expr {
    const l = parseBitOr();
    const t = peek();
    if (t.kind === "op" && ["<", "<=", ">", ">=", "==", "!="].includes(t.value)) {
      next();
      return { t: "bin", op: t.value, l, r: parseBitOr() };
    }
    if (t.kind === "id" && ["contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals"].includes(t.value)) {
      next();
      return { t: "bin", op: t.value, l, r: parseBitOr() };
    }
    if (t.kind === "id" && t.value === "matches") {
      next();
      const r = next();
      if (r.kind !== "regex") throw fail("matches needs a /regular expression/", r);
      let re: RegExp;
      try {
        re = new RegExp(r.value, r.flags ?? "");
      } catch (e) {
        throw fail(`Invalid regular expression: ${(e as Error).message}`, r);
      }
      return { t: "bin", op: "matches", l, r: { t: "regex", re } };
    }
    return l;
  }
  function binLevel(ops: string[], nextLevel: () => Expr): () => Expr {
    return () => {
      let l = nextLevel();
      while (peek().kind === "op" && ops.includes(peek().value)) {
        const op = next().value;
        l = { t: "bin", op, l, r: nextLevel() };
      }
      return l;
    };
  }
  function parseBitOr(): Expr {
    return binLevel(["|"], binLevel(["^"], binLevel(["&"], binLevel(["<<", ">>"], binLevel(["+", "-"], binLevel(["*", "\\", "%"], parseUnary))))))();
  }
  function parseUnary(): Expr {
    if (isOp("-")) {
      next();
      return { t: "neg", e: parseUnary() };
    }
    if (isOp("~")) {
      next();
      return { t: "bitnot", e: parseUnary() };
    }
    return parsePrimary();
  }
  function parseRange(): [Expr, Expr] {
    expectOp("(");
    const a = parseBitOr();
    expectOp("..");
    const b = parseBitOr();
    expectOp(")");
    return [a, b];
  }
  function parseSet(): string[] | "them" {
    if (isId("them")) {
      next();
      return "them";
    }
    expectOp("(");
    const ids: string[] = [];
    for (;;) {
      const t = next();
      if (t.kind === "strid") ids.push(t.value);
      else if (t.kind === "id") ids.push(`rule:${t.value}`);
      else throw fail("Expected $string or rule name in set", t);
      if (isOp(",")) next();
      else break;
    }
    expectOp(")");
    return ids;
  }
  function parseQuant(): Quant {
    if (isId("all") || isId("any") || isId("none")) return { kind: next().value as "all" | "any" | "none" };
    if (peek().kind === "num") {
      const n = next();
      if (isOp("%")) {
        next();
        return { kind: "pct", e: { t: "num", v: n.num! } };
      }
      return { kind: "num", e: { t: "num", v: n.num! } };
    }
    return { kind: "num", e: parsePrimary() };
  }
  function parseOf(quant: Quant): Expr {
    expectId("of");
    const set = parseSet();
    const e: Expr = { t: "of", quant, set, ruleSet: Array.isArray(set) && set.every((s) => s.startsWith("rule:")) ? set : undefined };
    if (Array.isArray(set) && !e.ruleSet && set.some((s) => s.startsWith("rule:"))) throw fail("A set cannot mix strings and rules");
    if (isId("in")) {
      next();
      e.range = parseRange();
    }
    return e;
  }
  function parsePrimary(): Expr {
    const t = peek();
    if (t.kind === "num") {
      const quantified = (peek(1).kind === "id" && peek(1).value === "of") || (peek(1).kind === "op" && peek(1).value === "%" && peek(2).kind === "id" && peek(2).value === "of");
      if (quantified) return parseOf(parseQuant());
      next();
      return { t: "num", v: t.num! };
    }
    if (t.kind === "str") {
      next();
      return { t: "str", v: t.value };
    }
    if (t.kind === "op" && t.value === "(") {
      next();
      const e = parseExpr();
      expectOp(")");
      return e;
    }
    if (t.kind === "strid") {
      next();
      const e: Expr = { t: "strmatch", id: t.value };
      if (isId("at")) {
        next();
        e.at = parseBitOr();
      } else if (isId("in")) {
        next();
        e.range = parseRange();
      }
      return e;
    }
    if (t.kind === "strcount") {
      next();
      const e: Expr = { t: "strcount", id: t.value };
      if (isId("in")) {
        next();
        e.range = parseRange();
      }
      return e;
    }
    if (t.kind === "stroffset" || t.kind === "strlen") {
      next();
      let index: Expr = { t: "num", v: 1 };
      if (isOp("[")) {
        next();
        index = parseExpr();
        expectOp("]");
      }
      return { t: t.kind, id: t.value, index };
    }
    if (t.kind === "id") {
      if (t.value === "true" || t.value === "false") {
        next();
        return { t: "bool", v: t.value === "true" };
      }
      if (t.value === "filesize") {
        next();
        return { t: "filesize" };
      }
      if (t.value === "entrypoint") {
        next();
        return { t: "entrypoint" };
      }
      if (t.value === "for") {
        next();
        const quant = parseQuant();
        if (isId("of")) {
          next();
          const set = parseSet();
          expectOp(":");
          expectOp("(");
          const body = parseExpr();
          expectOp(")");
          return { t: "forof", quant, set, body };
        }
        const vars = [expectId().value];
        while (isOp(",")) {
          next();
          vars.push(expectId().value);
        }
        expectId("in");
        let iter: { range: [Expr, Expr] } | { list: Expr[] };
        expectOp("(");
        const first = parseBitOr();
        if (isOp("..")) {
          next();
          const second = parseBitOr();
          expectOp(")");
          iter = { range: [first, second] };
        } else {
          const list = [first];
          while (isOp(",")) {
            next();
            list.push(parseBitOr());
          }
          expectOp(")");
          iter = { list };
        }
        expectOp(":");
        expectOp("(");
        const body = parseExpr();
        expectOp(")");
        return { t: "forin", quant, vars, iter, body };
      }
      // Quantified "of": all/any/none of …, or N of …
      if ((t.value === "all" || t.value === "any" || t.value === "none") && peek(1).kind === "id" && peek(1).value === "of") return parseOf(parseQuant());
      if (KEYWORDS.has(t.value)) throw fail(`Unexpected keyword '${t.value}'`);
      next();
      const path: (string | { index: Expr } | { call: Expr[] })[] = [t.value];
      for (;;) {
        if (isOp(".")) {
          next();
          path.push(expectId().value);
        } else if (isOp("[")) {
          next();
          const index = parseExpr();
          expectOp("]");
          path.push({ index });
        } else if (isOp("(")) {
          next();
          const args: Expr[] = [];
          if (!isOp(")")) {
            args.push(parseExpr());
            while (isOp(",")) {
              next();
              args.push(parseExpr());
            }
          }
          expectOp(")");
          path.push({ call: args });
        } else break;
      }
      return { t: "ident", path, line: t.line, col: t.col };
    }
    throw fail(`Unexpected '${t.value || "end of input"}'`);
  }
}

// ───────────────────────────── scanning

export interface StringMatch {
  offset: number;
  length: number;
  data: string;
}

export interface RuleResult {
  rule: string;
  tags: string[];
  meta: YaraRule["meta"];
  matched: boolean;
  strings: { id: string; matches: StringMatch[]; truncated: boolean }[];
  isPrivate: boolean;
}

export interface ScanResult {
  results: RuleResult[];
  durationMs: number;
  bytesScanned: number;
  warnings: string[];
}

const MAX_MATCHES_PER_STRING = 10_000;
export const MAX_SCAN_BYTES = 64 * 1024 * 1024;

type Val = boolean | number | string | undefined;

function isWordByte(b: number | undefined) {
  return b !== undefined && ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a));
}

export interface ScanContext {
  pe?: PeAnalysis | null;
}

export function scanYara(compiled: CompiledRules, data: Uint8Array, ctx: ScanContext = {}): ScanResult {
  const started = Date.now();
  const warnings: string[] = [];
  if (data.length > MAX_SCAN_BYTES) throw new Error(`Input is larger than ${MAX_SCAN_BYTES / 1024 / 1024} MB`);
  let text: string | null = null;
  const getText = () => {
    if (text === null) {
      const parts: string[] = [];
      for (let o = 0; o < data.length; o += 32768) parts.push(latin1(data.subarray(o, o + 32768)));
      text = parts.join("");
    }
    return text;
  };

  const ruleValues = new Map<string, boolean>();
  const results: RuleResult[] = [];

  for (const rule of compiled.rules) {
    const matches = new Map<string, StringMatch[]>();
    const truncated = new Set<string>();
    for (const s of rule.strings) {
      const list: StringMatch[] = [];
      const re = new RegExp(s.regex.source, s.regex.flags);
      const hay = getText();
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = re.exec(hay)) !== null) {
        if (m[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        const off = m.index;
        const len = m[0].length;
        const wide = s.modifiers.includes("wide") && len >= 2 && m[0].charCodeAt(1) === 0;
        if (!s.fullword || (!isWordByte(data[off - (wide ? 2 : 1)]) && !isWordByte(data[off + len]))) {
          list.push({ offset: off, length: len, data: m[0].slice(0, 64) });
          if (list.length >= MAX_MATCHES_PER_STRING) {
            truncated.add(s.id);
            break;
          }
        }
        // YARA reports overlapping matches; continue one byte after the start.
        re.lastIndex = off + 1;
        if (++guard > 5_000_000) break;
      }
      matches.set(s.id, list);
    }
    const env: Env = { rule, matches, data, getText, ruleValues, pe: ctx.pe ?? null, vars: new Map(), anon: null };
    let matched = false;
    try {
      matched = truthy(evalExpr(rule.condition, env));
    } catch (e) {
      warnings.push(`${rule.name}: ${(e as Error).message}`);
      matched = false;
    }
    ruleValues.set(rule.name, matched);
    results.push({
      rule: rule.name,
      tags: rule.tags,
      meta: rule.meta,
      matched,
      isPrivate: rule.isPrivate,
      strings: rule.strings.filter((s) => !s.isPrivate).map((s) => ({ id: s.id, matches: matches.get(s.id) ?? [], truncated: truncated.has(s.id) })),
    });
  }
  // A global rule that fails makes every rule in the namespace fail.
  if (compiled.rules.some((r) => r.isGlobal && !ruleValues.get(r.name))) for (const r of results) r.matched = false;
  return { results, durationMs: Date.now() - started, bytesScanned: data.length, warnings };
}

interface Env {
  rule: YaraRule;
  matches: Map<string, StringMatch[]>;
  data: Uint8Array;
  getText: () => string;
  ruleValues: Map<string, boolean>;
  pe: PeAnalysis | null;
  vars: Map<string, Val>;
  anon: string | null;
}

const truthy = (v: Val) => (typeof v === "number" ? v !== 0 : typeof v === "string" ? v.length > 0 : v === true);

function idsFor(set: string[] | "them", rule: YaraRule): string[] {
  if (set === "them") return rule.strings.map((s) => s.id);
  const out: string[] = [];
  for (const id of set) {
    if (id.endsWith("*")) out.push(...rule.strings.filter((s) => s.id.startsWith(id.slice(0, -1))).map((s) => s.id));
    else out.push(id);
  }
  return [...new Set(out)];
}

function quantOk(q: Quant, hits: number, total: number, env: Env): boolean {
  if (!("e" in q)) return q.kind === "all" ? hits === total : q.kind === "any" ? hits >= 1 : hits === 0;
  const n = evalExpr(q.e, env);
  if (typeof n !== "number") return false;
  if (q.kind === "pct") return hits >= Math.ceil((n / 100) * total);
  return hits >= n;
}

function readInt(data: Uint8Array, off: number, size: 1 | 2 | 4, signed: boolean, be: boolean): number | undefined {
  if (off < 0 || off + size > data.length) return undefined;
  const v = new DataView(data.buffer, data.byteOffset + off, size);
  if (size === 1) return signed ? v.getInt8(0) : v.getUint8(0);
  if (size === 2) return signed ? v.getInt16(0, !be) : v.getUint16(0, !be);
  return signed ? v.getInt32(0, !be) : v.getUint32(0, !be);
}

function evalExpr(e: Expr, env: Env): Val {
  switch (e.t) {
    case "bool":
      return e.v;
    case "num":
      return e.v;
    case "str":
      return e.v;
    case "regex":
      return undefined;
    case "filesize":
      return env.data.length;
    case "entrypoint":
      return env.pe ? peEntryOffset(env.pe) : undefined;
    case "not": {
      const v = evalExpr(e.e, env);
      return v === undefined ? undefined : !truthy(v);
    }
    case "and":
      return truthy(evalExpr(e.l, env)) && truthy(evalExpr(e.r, env));
    case "or":
      return truthy(evalExpr(e.l, env)) || truthy(evalExpr(e.r, env));
    case "neg": {
      const v = evalExpr(e.e, env);
      return typeof v === "number" ? -v : undefined;
    }
    case "bitnot": {
      const v = evalExpr(e.e, env);
      return typeof v === "number" ? ~v : undefined;
    }
    case "bin": {
      const l = evalExpr(e.l, env);
      if (e.op === "matches") return typeof l === "string" ? (e.r as { re: RegExp }).re.test(l) : undefined;
      const r = evalExpr(e.r, env);
      if (l === undefined || r === undefined) return undefined;
      if (typeof l === "string" && typeof r === "string") {
        const L = l.toLowerCase();
        const R = r.toLowerCase();
        switch (e.op) {
          case "==":
            return l === r;
          case "!=":
            return l !== r;
          case "contains":
            return l.includes(r);
          case "icontains":
            return L.includes(R);
          case "startswith":
            return l.startsWith(r);
          case "istartswith":
            return L.startsWith(R);
          case "endswith":
            return l.endsWith(r);
          case "iendswith":
            return L.endsWith(R);
          case "iequals":
            return L === R;
        }
        return undefined;
      }
      const a = typeof l === "boolean" ? Number(l) : l;
      const b = typeof r === "boolean" ? Number(r) : r;
      if (typeof a !== "number" || typeof b !== "number") return undefined;
      switch (e.op) {
        case "<":
          return a < b;
        case "<=":
          return a <= b;
        case ">":
          return a > b;
        case ">=":
          return a >= b;
        case "==":
          return a === b;
        case "!=":
          return a !== b;
        case "+":
          return a + b;
        case "-":
          return a - b;
        case "*":
          return a * b;
        case "\\":
          return b === 0 ? undefined : Math.trunc(a / b);
        case "%":
          return b === 0 ? undefined : a % b;
        case "&":
          return a & b;
        case "|":
          return a | b;
        case "^":
          return a ^ b;
        case "<<":
          return a << b;
        case ">>":
          return a >>> b;
      }
      return undefined;
    }
    case "strmatch": {
      const id = e.id || env.anon!;
      const list = env.matches.get(id) ?? [];
      if (e.at) {
        const at = evalExpr(e.at, env);
        return typeof at === "number" ? list.some((m) => m.offset === at) : undefined;
      }
      if (e.range) {
        const a = evalExpr(e.range[0], env);
        const b = evalExpr(e.range[1], env);
        if (typeof a !== "number" || typeof b !== "number") return undefined;
        return list.some((m) => m.offset >= a && m.offset <= b);
      }
      return list.length > 0;
    }
    case "strcount": {
      const list = env.matches.get(e.id || env.anon!) ?? [];
      if (e.range) {
        const a = evalExpr(e.range[0], env);
        const b = evalExpr(e.range[1], env);
        if (typeof a !== "number" || typeof b !== "number") return undefined;
        return list.filter((m) => m.offset >= a && m.offset <= b).length;
      }
      return list.length;
    }
    case "stroffset":
    case "strlen": {
      const list = env.matches.get(e.id || env.anon!) ?? [];
      const i = evalExpr(e.index, env);
      if (typeof i !== "number" || i < 1 || i > list.length) return undefined;
      return e.t === "stroffset" ? list[i - 1].offset : list[i - 1].length;
    }
    case "of": {
      if (e.ruleSet) {
        const names = e.ruleSet.map((r) => r.slice(5));
        const hits = names.filter((n) => env.ruleValues.get(n)).length;
        return quantOk(e.quant, hits, names.length, env);
      }
      const ids = idsFor(e.set, env.rule);
      let hits = 0;
      for (const id of ids) {
        const list = env.matches.get(id) ?? [];
        if (e.range) {
          const a = evalExpr(e.range[0], env);
          const b = evalExpr(e.range[1], env);
          if (typeof a === "number" && typeof b === "number" && list.some((m) => m.offset >= a && m.offset <= b)) hits++;
        } else if (list.length) hits++;
      }
      return quantOk(e.quant, hits, ids.length, env);
    }
    case "forof": {
      const ids = idsFor(e.set, env.rule);
      let hits = 0;
      const prev = env.anon;
      for (const id of ids) {
        env.anon = id;
        if (truthy(evalExpr(e.body, env))) hits++;
      }
      env.anon = prev;
      return quantOk(e.quant, hits, ids.length, env);
    }
    case "forin": {
      let items: Val[] = [];
      if ("range" in e.iter) {
        const a = evalExpr(e.iter.range[0], env);
        const b = evalExpr(e.iter.range[1], env);
        if (typeof a !== "number" || typeof b !== "number") return undefined;
        if (b - a > 1_000_000) throw new Error("for-loop range is too large (over 1,000,000 iterations)");
        for (let i = a; i <= b; i++) items.push(i);
      } else items = e.iter.list.map((x) => evalExpr(x, env));
      let hits = 0;
      const saved = new Map(env.vars);
      for (const item of items) {
        env.vars.set(e.vars[0], item);
        if (truthy(evalExpr(e.body, env))) hits++;
      }
      env.vars = saved;
      return quantOk(e.quant, hits, items.length, env);
    }
    case "ident":
      return evalIdent(e, env);
  }
}

function peEntryOffset(pe: PeAnalysis): number | undefined {
  const s = pe.sections.find((x) => x.name === pe.entrySection);
  if (!s) return undefined;
  return pe.entryPoint - s.virtualAddress + s.rawOffset;
}

const PE_CONSTANTS: Record<string, number> = {
  MACHINE_I386: 0x14c,
  MACHINE_AMD64: 0x8664,
  MACHINE_ARM: 0x1c0,
  MACHINE_ARMNT: 0x1c4,
  MACHINE_ARM64: 0xaa64,
  MACHINE_IA64: 0x200,
  RELOCS_STRIPPED: 0x0001,
  EXECUTABLE_IMAGE: 0x0002,
  LARGE_ADDRESS_AWARE: 0x0020,
  DEBUG_STRIPPED: 0x0200,
  SYSTEM: 0x1000,
  DLL: 0x2000,
  SUBSYSTEM_NATIVE: 1,
  SUBSYSTEM_WINDOWS_GUI: 2,
  SUBSYSTEM_WINDOWS_CUI: 3,
  SECTION_CNT_CODE: 0x20,
  SECTION_CNT_INITIALIZED_DATA: 0x40,
  SECTION_CNT_UNINITIALIZED_DATA: 0x80,
  SECTION_MEM_EXECUTE: 0x20000000,
  SECTION_MEM_READ: 0x40000000,
  SECTION_MEM_WRITE: 0x80000000,
  DYNAMIC_BASE: 0x0040,
  NX_COMPAT: 0x0100,
  GUARD_CF: 0x4000,
  HIGH_ENTROPY_VA: 0x0020,
};

function flagValue(names: string[], table: Record<string, number>): number {
  return names.reduce((n, f) => n | (table[f] ?? 0), 0);
}

function evalIdent(e: Extract<Expr, { t: "ident" }>, env: Env): Val {
  const [head, ...rest] = e.path;
  const unsupported = () => {
    throw new Error(`${e.path.map((p) => (typeof p === "string" ? p : "index" in p ? "[…]" : "(…)")).join(".").replace(/\.\[/g, "[").replace(/\.\(/g, "(")} is not supported by this engine`);
  };
  if (typeof head !== "string") return unsupported();
  if (!rest.length) {
    if (env.vars.has(head)) return env.vars.get(head);
    if (env.ruleValues.has(head)) return env.ruleValues.get(head);
    throw new Error(`Unknown identifier '${head}' (rules can only reference rules defined above them)`);
  }
  const call = rest[0] && typeof rest[0] !== "string" && "call" in rest[0] ? rest[0].call.map((a) => evalExpr(a, env)) : null;

  // uint8(off) … int32be(off)
  const intFn = /^(u?)int(8|16|32)(be)?$/.exec(head);
  if (intFn && call) {
    const off = call[0];
    if (typeof off !== "number") return undefined;
    return readInt(env.data, off, (Number(intFn[2]) / 8) as 1 | 2 | 4, intFn[1] !== "u", !!intFn[3]);
  }
  if (head === "math" && typeof rest[0] === "string") {
    const fn = rest[0];
    const args = rest[1] && typeof rest[1] !== "string" && "call" in rest[1] ? rest[1].call.map((a) => evalExpr(a, env)) : null;
    if (!args) return unsupported();
    const range = (): [number, number] | undefined => {
      const [o, s] = args;
      if (typeof o !== "number" || typeof s !== "number" || o < 0 || o > env.data.length) return undefined;
      return [o, Math.min(env.data.length, o + s)];
    };
    if (fn === "entropy") {
      if (typeof args[0] === "string") {
        const b = Uint8Array.from(args[0], (c) => c.charCodeAt(0) & 0xff);
        return entropy(b);
      }
      const r = range();
      return r ? entropy(env.data, r[0], r[1]) : undefined;
    }
    if (fn === "mean") {
      const r = range();
      if (!r || r[1] <= r[0]) return undefined;
      let sum = 0;
      for (let i = r[0]; i < r[1]; i++) sum += env.data[i];
      return sum / (r[1] - r[0]);
    }
    if (fn === "in_range") {
      const [v, lo, hi] = args;
      return typeof v === "number" && typeof lo === "number" && typeof hi === "number" ? v >= lo && v <= hi : undefined;
    }
    if (fn === "count" || fn === "percentage") {
      const [byte, o, s] = args;
      if (typeof byte !== "number") return undefined;
      const start = typeof o === "number" ? o : 0;
      const end = typeof s === "number" ? Math.min(env.data.length, start + s) : env.data.length;
      let n = 0;
      for (let i = start; i < end; i++) if (env.data[i] === byte) n++;
      return fn === "count" ? n : end > start ? n / (end - start) : undefined;
    }
    return unsupported();
  }
  if (head === "hash" && typeof rest[0] === "string") {
    const fn = rest[0];
    const args = rest[1] && typeof rest[1] !== "string" && "call" in rest[1] ? rest[1].call.map((a) => evalExpr(a, env)) : null;
    if (!args) return unsupported();
    let bytes: Uint8Array | undefined;
    if (typeof args[0] === "string") bytes = Uint8Array.from(args[0], (c) => c.charCodeAt(0) & 0xff);
    else if (typeof args[0] === "number" && typeof args[1] === "number") bytes = env.data.subarray(args[0], Math.min(env.data.length, args[0] + args[1]));
    if (!bytes) return undefined;
    if (fn === "md5") return md5(bytes);
    if (fn === "sha256") return sha256Sync(bytes);
    return unsupported();
  }
  if (head === "pe") {
    const pe = env.pe;
    const name = rest[0];
    if (typeof name !== "string") return unsupported();
    if (name in PE_CONSTANTS && rest.length === 1) return PE_CONSTANTS[name];
    if (name === "is_pe") return !!pe;
    if (!pe) return undefined;
    const args = rest[1] && typeof rest[1] !== "string" && "call" in rest[1] ? rest[1].call.map((a) => evalExpr(a, env)) : null;
    switch (name) {
      case "is_dll":
        return pe.isDll;
      case "is_32bit":
        return !pe.is64;
      case "is_64bit":
        return pe.is64;
      case "machine":
        return pe.machine;
      case "number_of_sections":
        return pe.sections.length;
      case "timestamp":
        return pe.timestamp;
      case "entry_point":
        return peEntryOffset(pe);
      case "entry_point_raw":
        return pe.entryPoint;
      case "subsystem":
        return Number(Object.entries({ 1: "Native", 2: "Windows GUI", 3: "Windows console" }).find(([, v]) => pe.subsystem.startsWith(v))?.[0] ?? 0);
      case "characteristics":
        return flagValue(pe.characteristics, { RELOCS_STRIPPED: 1, EXECUTABLE_IMAGE: 2, LARGE_ADDRESS_AWARE: 0x20, "32BIT_MACHINE": 0x100, DEBUG_STRIPPED: 0x200, SYSTEM: 0x1000, DLL: 0x2000 });
      case "dll_characteristics":
        return flagValue(pe.dllCharacteristics, PE_CONSTANTS);
      case "number_of_resources":
        return pe.resources.length;
      case "number_of_imports":
        return pe.imports.filter((i) => !i.delayed).length;
      case "number_of_imported_functions":
        return pe.importCount;
      case "number_of_exports":
        return pe.exports.entries.length;
      case "number_of_signatures":
        return pe.signature.present ? 1 + pe.signature.nestedSignatures : 0;
      case "overlay": {
        const field = rest[1];
        if (field === "offset") return pe.overlay?.offset ?? 0;
        if (field === "size") return pe.overlay?.size ?? 0;
        return unsupported();
      }
      case "imphash":
        if (!args) return unsupported();
        return pe.imphash;
      case "imports": {
        if (!args) return unsupported();
        const [dll, fn] = args;
        if (typeof dll !== "string") return undefined;
        const libs = pe.imports.filter((i) => !i.delayed && i.dll.toLowerCase() === dll.toLowerCase());
        if (fn === undefined) return libs.reduce((n, l) => n + l.functions.length, 0);
        if (typeof fn === "number") return libs.some((l) => l.functions.some((f) => f.ordinal === fn)) ? 1 : 0;
        return libs.some((l) => l.functions.some((f) => f.name === fn)) ? 1 : 0;
      }
      case "exports": {
        if (!args) return unsupported();
        const [fn] = args;
        if (typeof fn === "number") return pe.exports.entries.some((x) => x.ordinal === fn);
        return typeof fn === "string" ? pe.exports.entries.some((x) => x.name === fn) : undefined;
      }
      case "sections": {
        const idx = rest[1];
        const field = rest[2];
        if (!idx || typeof idx === "string" || !("index" in idx) || typeof field !== "string") return unsupported();
        const i = evalExpr(idx.index, env);
        if (typeof i !== "number") return undefined;
        const s = pe.sections[i];
        if (!s) return undefined;
        switch (field) {
          case "name":
            return s.name;
          case "virtual_address":
            return s.virtualAddress;
          case "virtual_size":
            return s.virtualSize;
          case "raw_data_offset":
            return s.rawOffset;
          case "raw_data_size":
            return s.rawSize;
          case "characteristics":
            return s.characteristics;
        }
        return unsupported();
      }
      case "version_info": {
        const idx = rest[1];
        if (!idx || typeof idx === "string" || !("index" in idx)) return unsupported();
        const k = evalExpr(idx.index, env);
        return typeof k === "string" ? pe.version[k] : undefined;
      }
      case "pdb_path":
        return pe.debug.find((d) => d.pdb)?.pdb;
    }
    return unsupported();
  }
  return unsupported();
}
