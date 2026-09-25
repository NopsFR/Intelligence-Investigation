// Compares lists of hashes (or any tokens) across named sets: which values
// appear in every set, which are unique to one, and where each occurs.
// Pure client-side text processing — nothing is sent anywhere.

export interface HashSet {
  label: string;
  values: string[];
}

export interface CompareRow {
  value: string;
  sets: string[];
  count: number;
}

export interface CompareResult {
  rows: CompareRow[];
  inAll: number;
  onlyOne: number;
  setCount: number;
}

const HASH_KIND: [RegExp, string][] = [
  [/^[a-f0-9]{32}$/i, "MD5"],
  [/^[a-f0-9]{40}$/i, "SHA-1"],
  [/^[a-f0-9]{64}$/i, "SHA-256"],
  [/^[a-f0-9]{128}$/i, "SHA-512"],
];

export function hashKind(value: string): string | null {
  for (const [re, name] of HASH_KIND) if (re.test(value)) return name;
  return null;
}

/** Splits free text into tokens: one per line, or comma/whitespace separated; a leading "label," or "label:" is stripped if the remainder looks like a hash. */
export function parseHashList(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    for (const tok of line.split(/[\s,;]+/)) {
      const v = tok.trim().toLowerCase();
      if (hashKind(v)) out.push(v);
    }
  }
  return [...new Set(out)];
}

export function compareHashSets(sets: HashSet[]): CompareResult {
  const named = sets.filter((s) => s.label.trim());
  const map = new Map<string, Set<string>>();
  for (const s of named) for (const v of s.values) {
    const entry = map.get(v) ?? new Set<string>();
    entry.add(s.label);
    map.set(v, entry);
  }
  const rows: CompareRow[] = [...map.entries()]
    .map(([value, setNames]) => ({ value, sets: [...setNames], count: setNames.size }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
  return {
    rows,
    inAll: rows.filter((r) => r.count === named.length && named.length > 0).length,
    onlyOne: rows.filter((r) => r.count === 1).length,
    setCount: named.length,
  };
}
