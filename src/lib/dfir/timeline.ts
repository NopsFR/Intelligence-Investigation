// Builds a merged, sorted timeline from pasted log text (one or more named
// sources). Recognises a leading timestamp in several common formats; the
// rest of the line is kept as the event text. Lines with no recognisable
// timestamp are skipped and reported, never silently reordered.

export interface TimelineEvent {
  iso: string;
  source: string;
  raw: string;
  text: string;
  line: number;
}

export interface TimelineResult {
  events: TimelineEvent[];
  skipped: number;
  sources: string[];
}

// Ordered by specificity; each captures a timestamp then the remainder.
const PATTERNS: [RegExp, (m: RegExpMatchArray) => Date | null][] = [
  // ISO 8601: 2026-09-25T09:12:01.101Z or with space, optional offset
  [/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*[-:,]?\s*(.*)$/, (m) => new Date(m[1].replace(" ", "T"))],
  // Windows Event Log: 09/25/2026 09:12:01 AM
  [/^(\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s*[-:,]?\s*(.*)$/i, (m) => new Date(m[1])],
  // syslog: Sep 25 09:12:01 (no year — assume current year)
  [/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)$/, (m) => new Date(`${m[1]} ${new Date().getUTCFullYear()} UTC`)],
  // Apache/nginx combined log: [25/Sep/2026:09:12:01 +0000]
  [/^\[?(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]?\s*(.*)$/, (m) => parseApacheDate(m[1])],
  // Epoch seconds or milliseconds at line start
  [/^(\d{10,13})\s*[-:,]?\s*(.*)$/, (m) => new Date(Number(m[1]) * (m[1].length === 10 ? 1000 : 1))],
];

function parseApacheDate(s: string): Date | null {
  const m = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{2})(\d{2})$/.exec(s);
  if (!m) return null;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const month = months.indexOf(m[2]);
  if (month < 0) return null;
  return new Date(`${m[3]}-${String(month + 1).padStart(2, "0")}-${m[1]}T${m[4]}:${m[5]}:${m[6]}${m[7]}:${m[8]}`);
}

function parseLine(line: string): { iso: string; text: string } | null {
  for (const [re, toDate] of PATTERNS) {
    const m = re.exec(line);
    if (!m) continue;
    const d = toDate(m);
    if (!d || Number.isNaN(d.getTime())) continue;
    return { iso: d.toISOString(), text: (m[2] ?? "").trim() || line };
  }
  return null;
}

export function buildTimeline(sources: { label: string; text: string }[]): TimelineResult {
  const events: TimelineEvent[] = [];
  let skipped = 0;
  for (const s of sources) {
    if (!s.label.trim() || !s.text.trim()) continue;
    s.text.split(/\r?\n/).forEach((raw, i) => {
      const line = raw.trim();
      if (!line) return;
      const parsed = parseLine(line);
      if (!parsed) {
        skipped++;
        return;
      }
      events.push({ iso: parsed.iso, source: s.label.trim(), raw: line, text: parsed.text, line: i + 1 });
    });
  }
  events.sort((a, b) => a.iso.localeCompare(b.iso));
  return { events, skipped, sources: [...new Set(events.map((e) => e.source))] };
}
