// Builds a process tree from pasted process listings. Two input shapes are
// recognised: delimited tables (CSV/TSV with pid/ppid/name[/commandline]
// headers) and Sysmon-style key:value blocks (Event ID 1 "Process Create").
// Parsing only — nothing here inspects, runs or touches a real process.

export interface ProcessNode {
  pid: string;
  ppid?: string;
  name: string;
  commandLine?: string;
  user?: string;
  image?: string;
  time?: string;
  children: ProcessNode[];
}

export interface ProcessParseResult {
  format: "table" | "sysmon" | "unknown";
  roots: ProcessNode[];
  orphans: ProcessNode[];
  total: number;
  warnings: string[];
}

const HEADER_ALIASES: Record<string, string[]> = {
  pid: ["pid", "processid", "process id"],
  ppid: ["ppid", "parentpid", "parentprocessid", "parent process id"],
  name: ["name", "image name", "imagename", "process", "processname"],
  commandline: ["commandline", "command line", "cmd", "cmdline"],
  user: ["user", "username", "user name"],
};

function detectDelimiter(line: string): string | null {
  if (line.includes("\t")) return "\t";
  if (line.includes(",")) return ",";
  if (/\s{2,}/.test(line)) return /\s{2,}/.source;
  return null;
}

function parseTable(text: string): ProcessNode[] | null {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return null;
  const delim = detectDelimiter(lines[0]);
  if (!delim) return null;
  const split = (l: string) => l.split(new RegExp(delim)).map((c) => c.trim().replace(/^"|"$/g, ""));
  const header = split(lines[0]).map((h) => h.toLowerCase());
  const colIndex = (key: string) => header.findIndex((h) => HEADER_ALIASES[key].includes(h));
  const pidCol = colIndex("pid");
  const nameCol = colIndex("name");
  if (pidCol < 0 || nameCol < 0) return null;
  const ppidCol = colIndex("ppid");
  const cmdCol = colIndex("commandline");
  const userCol = colIndex("user");
  const nodes: ProcessNode[] = [];
  for (const line of lines.slice(1)) {
    const cells = split(line);
    if (cells.length <= pidCol || cells.length <= nameCol) continue;
    const pid = cells[pidCol];
    if (!pid) continue;
    nodes.push({ pid, ppid: ppidCol >= 0 ? cells[ppidCol] || undefined : undefined, name: cells[nameCol], commandLine: cmdCol >= 0 ? cells[cmdCol] || undefined : undefined, user: userCol >= 0 ? cells[userCol] || undefined : undefined, children: [] });
  }
  return nodes.length ? nodes : null;
}

/** Sysmon Event ID 1 (and similar EDR exports) as repeated Key: Value blocks separated by blank lines or "Event". */
function parseSysmonBlocks(text: string): ProcessNode[] | null {
  const blocks = text.split(/\n\s*\n|(?=^-+$)|(?=Process (?:Create|Creation):)/im).filter((b) => /process\s*id/i.test(b));
  if (!blocks.length) return null;
  const nodes: ProcessNode[] = [];
  for (const block of blocks) {
    const get = (re: RegExp) => re.exec(block)?.[1]?.trim();
    const pid = get(/\bProcessId:\s*(\d+)/i);
    if (!pid) continue;
    const ppid = get(/\bParentProcessId:\s*(\d+)/i);
    const image = get(/^\s*Image:\s*(.+)$/im);
    const parentImage = get(/^\s*ParentImage:\s*(.+)$/im);
    const cmd = get(/^\s*CommandLine:\s*(.+)$/im);
    const user = get(/^\s*User:\s*(.+)$/im);
    const time = get(/^\s*UtcTime:\s*(.+)$/im) ?? get(/^\s*(?:TimeCreated|Timestamp):\s*(.+)$/im);
    const name = image ? image.split(/[\\/]/).pop()! : `PID ${pid}`;
    nodes.push({ pid, ppid, name, image, commandLine: cmd, user, time, children: [] });
    void parentImage;
  }
  return nodes.length ? nodes : null;
}

export function parseProcessListing(text: string): ProcessParseResult {
  const warnings: string[] = [];
  let format: ProcessParseResult["format"] = "unknown";
  let flat: ProcessNode[] | null = parseSysmonBlocks(text);
  if (flat) format = "sysmon";
  else {
    flat = parseTable(text);
    if (flat) format = "table";
  }
  if (!flat) return { format: "unknown", roots: [], orphans: [], total: 0, warnings: ["Could not recognise the format. Paste a CSV/TSV table with pid/ppid/name columns, or Sysmon-style ProcessId/ParentProcessId blocks."] };

  const byPid = new Map<string, ProcessNode>();
  for (const n of flat) {
    if (byPid.has(n.pid)) warnings.push(`Duplicate PID ${n.pid}; keeping the first occurrence`);
    else byPid.set(n.pid, n);
  }
  const roots: ProcessNode[] = [];
  const orphans: ProcessNode[] = [];
  const noParent = (ppid: string | undefined) => !ppid || ppid === "0";
  for (const n of byPid.values()) {
    if (noParent(n.ppid)) roots.push(n);
    else if (byPid.has(n.ppid!) && n.ppid !== n.pid) byPid.get(n.ppid!)!.children.push(n);
    else orphans.push(n); // parent not in this listing
  }
  const sortTree = (list: ProcessNode[]) => {
    list.sort((a, b) => Number(a.pid) - Number(b.pid) || a.name.localeCompare(b.name));
    for (const n of list) sortTree(n.children);
  };
  sortTree(roots);
  sortTree(orphans);
  return { format, roots, orphans, total: byPid.size, warnings };
}
