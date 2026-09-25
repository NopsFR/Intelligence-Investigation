import type { Token } from "@/components/ui/workbench";

// Line-at-a-time tokenizers for the two rule languages. Best-effort visual
// highlighting only; the real parsers in yara.ts / sigma.ts decide meaning.

const YARA_KEYWORDS = new Set(["rule", "private", "global", "meta", "strings", "condition", "import", "and", "or", "not", "at", "in", "of", "them", "all", "any", "none", "for", "true", "false", "filesize", "entrypoint", "contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals", "matches"]);
const YARA_MODIFIERS = new Set(["nocase", "wide", "ascii", "fullword", "xor", "base64", "base64wide", "private"]);

export function tokenizeYara(line: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === "/" && line.slice(i, i + 2) === "//") {
      out.push({ text: line.slice(i), kind: "comment" });
      break;
    }
    if (/\s/.test(c)) {
      let j = i;
      while (j < line.length && /\s/.test(line[j])) j++;
      out.push({ text: line.slice(i, j) });
      i = j;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < line.length && line[j] !== '"') j += line[j] === "\\" ? 2 : 1;
      j = Math.min(line.length, j + 1);
      out.push({ text: line.slice(i, j), kind: "string" });
      i = j;
      continue;
    }
    if (c === "$" || c === "#" || c === "@" || c === "!") {
      let j = i + 1;
      while (j < line.length && /[A-Za-z0-9_*]/.test(line[j])) j++;
      out.push({ text: line.slice(i, j), kind: "meta" });
      i = j;
      continue;
    }
    if (c === "{") {
      const end = line.indexOf("}", i);
      const j = end < 0 ? line.length : end + 1;
      out.push({ text: line.slice(i, j), kind: "hex" });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < line.length && /[A-Za-z0-9_]/.test(line[j])) j++;
      const word = line.slice(i, j);
      out.push({ text: word, kind: YARA_KEYWORDS.has(word) ? "keyword" : YARA_MODIFIERS.has(word) ? "tag" : "identifier" });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      while (j < line.length && /[0-9a-fA-Fx.]/.test(line[j])) j++;
      out.push({ text: line.slice(i, j), kind: "number" });
      i = j;
      continue;
    }
    out.push({ text: c, kind: "operator" });
    i++;
  }
  return out;
}

export function tokenizeYaml(line: string): Token[] {
  const out: Token[] = [];
  const commentIdx = line.indexOf("#");
  const indentMatch = /^\s*/.exec(line)![0];
  if (indentMatch) out.push({ text: indentMatch });
  const body = line.slice(indentMatch.length);
  if (commentIdx >= 0 && commentIdx >= indentMatch.length) {
    const code = line.slice(indentMatch.length, commentIdx);
    if (code) out.push(...tokenizeYamlBody(code));
    out.push({ text: line.slice(commentIdx), kind: "comment" });
    return out;
  }
  out.push(...tokenizeYamlBody(body));
  return out;
}

function tokenizeYamlBody(body: string): Token[] {
  if (/^-\s/.test(body) || body === "-") {
    return [{ text: "-", kind: "operator" }, ...(body.length > 1 ? tokenizeYamlBody(body.slice(1)) : [])];
  }
  const kv = /^([A-Za-z0-9_.|\-]+)(\s*:)(\s*)(.*)$/.exec(body);
  if (kv) {
    const [, key, colon, sp, value] = kv;
    const out: Token[] = [{ text: key, kind: "key" }, { text: colon, kind: "operator" }];
    if (sp) out.push({ text: sp });
    if (value) out.push(...valueTokens(value));
    return out;
  }
  return valueTokens(body);
}

function valueTokens(value: string): Token[] {
  if (/^['"]/.test(value)) return [{ text: value, kind: "string" }];
  if (/^(true|false|null|~)$/.test(value.trim())) return [{ text: value, kind: "keyword" }];
  if (/^-?\d+(\.\d+)?$/.test(value.trim())) return [{ text: value, kind: "number" }];
  if (/^\|$|^>$/.test(value.trim())) return [{ text: value, kind: "operator" }];
  return [{ text: value }];
}
