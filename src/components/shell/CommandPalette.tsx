"use client";

import { ArrowRight, Clock, Crosshair, Loader2, PanelLeft, Radar, Rows3, Search, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { OBSERVABLE_SHORT, type InvestigationSummary } from "@/lib/core/types";
import { cx } from "@/lib/client/cx";
import { useDetection } from "@/lib/client/detect";
import { relative } from "@/lib/client/format";
import { useInvestigate } from "@/lib/client/investigate";
import { usePrefs } from "@/lib/client/prefs";
import { InvestigationStatusBadge, TypeTag } from "@/components/ui/badges";
import { Kbd } from "@/components/ui/primitives";
import { NAV } from "./nav";

interface Command {
  id: string;
  group: string;
  label: ReactNode;
  hint?: ReactNode;
  icon: ReactNode;
  keywords: string;
  run: () => void;
}

interface AttackHit {
  id: string;
  kind: string;
  name: string;
  detail: string;
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [recent, setRecent] = useState<InvestigationSummary[] | null>(null);
  const [attack, setAttack] = useState<AttackHit[]>([]);
  const [loadingAttack, setLoadingAttack] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const { detection } = useDetection(query, 90);
  const { start } = useInvestigate();
  const { prefs, setPref } = usePrefs();
  const listId = useId();

  useEffect(() => {
    if (!open) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- reset palette on open
    setQuery("");
    setActive(0);
    const t = setTimeout(() => inputRef.current?.focus(), 10);
    return () => clearTimeout(t);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/investigations?limit=7${query.trim() ? `&q=${encodeURIComponent(query.trim())}` : ""}`, { signal: controller.signal });
        if (res.ok) setRecent(((await res.json()) as { items: InvestigationSummary[] }).items);
      } catch {
        /* ignore */
      }
    }, 120);
    return () => {
      clearTimeout(t);
      controller.abort();
    };
  }, [open, query]);

  useEffect(() => {
    const q = query.trim();
    if (!open || q.length < 2 || detection?.type) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- clear stale ATT&CK results
      setAttack([]);
      return;
    }
    setLoadingAttack(true);
    const controller = new AbortController();
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/attack/search?q=${encodeURIComponent(q)}`, { signal: controller.signal });
        if (res.ok) setAttack(((await res.json()) as { results: AttackHit[] }).results.slice(0, 6));
      } catch {
        /* ignore */
      } finally {
        if (!controller.signal.aborted) setLoadingAttack(false);
      }
    }, 160);
    return () => {
      clearTimeout(t);
      controller.abort();
    };
  }, [open, query, detection?.type]);

  const commands = useMemo<Command[]>(() => {
    const go = (href: string) => () => {
      onClose();
      router.push(href);
    };
    const q = query.trim().toLowerCase();
    const list: Command[] = [];
    if (detection?.type && detection.normalized) {
      const obs = query.trim();
      list.push(
        { id: "quick", group: "Investigate", label: <>Quick scan <span className="mono text-fg-1">{detection.normalized}</span></>, hint: <TypeTag type={detection.type} />, icon: <Radar size={15} />, keywords: q, run: () => (onClose(), void start(obs, "QUICK")) },
        { id: "deep", group: "Investigate", label: <>Deep investigation <span className="mono text-fg-1">{detection.normalized}</span></>, hint: <span className="label">Operator</span>, icon: <Crosshair size={15} className="text-signal" />, keywords: q, run: () => (onClose(), void start(obs, "DEEP")) }
      );
    }
    for (const r of recent ?? []) {
      list.push({
        id: `inv-${r.id}`,
        group: q ? "Matching investigations" : "Recent investigations",
        label: <span className="mono">{r.normalizedObservable}</span>,
        hint: (
          <span className="flex items-center gap-3">
            <InvestigationStatusBadge status={r.status} />
            <span className="text-xs text-fg-4">{relative(r.createdAt)}</span>
          </span>
        ),
        icon: <span className="mono w-[15px] text-center text-[9px] text-fg-3">{OBSERVABLE_SHORT[r.observableType].slice(0, 4)}</span>,
        keywords: `${r.normalizedObservable} ${r.observable}`.toLowerCase(),
        run: go(`/investigations/${r.id}`),
      });
    }
    for (const a of attack) {
      list.push({ id: `att-${a.id}`, group: "MITRE ATT&CK", label: <>{a.name}</>, hint: <span className="mono text-xs text-fg-3">{a.id} · {a.detail}</span>, icon: <Crosshair size={15} />, keywords: `${a.id} ${a.name}`.toLowerCase(), run: go(`/attack/${a.id}`) });
    }
    for (const g of NAV) {
      for (const item of g.items) {
        const Icon = item.icon;
        list.push({ id: `nav-${item.href}`, group: "Go to", label: item.label, hint: item.shortcut ? <span className="flex gap-1">{item.shortcut.split(" ").map((k) => <Kbd key={k}>{k}</Kbd>)}</span> : undefined, icon: <Icon size={15} />, keywords: `${item.label} ${g.group}`.toLowerCase(), run: go(item.href) });
      }
    }
    list.push(
      { id: "act-rail", group: "Preferences", label: prefs.rail === "collapsed" ? "Expand navigation rail" : "Collapse navigation rail", icon: <PanelLeft size={15} />, keywords: "rail sidebar navigation collapse expand", run: () => (setPref("rail", prefs.rail === "collapsed" ? "expanded" : "collapsed"), onClose()) },
      { id: "act-density", group: "Preferences", label: prefs.density === "compact" ? "Comfortable density" : "Compact density", icon: <Rows3 size={15} />, keywords: "density compact comfortable rows", run: () => (setPref("density", prefs.density === "compact" ? "comfortable" : "compact"), onClose()) },
      { id: "act-tz", group: "Preferences", label: prefs.tz === "utc" ? "Show times in local time" : "Show times in UTC", icon: <Clock size={15} />, keywords: "timezone utc local time", run: () => (setPref("tz", prefs.tz === "utc" ? "local" : "utc"), onClose()) },
      { id: "act-operator", group: "Preferences", label: "Operator session…", icon: <ShieldCheck size={15} />, keywords: "operator login unlock token session security", run: go("/settings?section=security") }
    );
    // Investigations, detections and ATT&CK hits are already server-filtered; filter the rest locally.
    return list.filter((c) => !q || c.group === "Investigate" || c.group === "MITRE ATT&CK" || c.id.startsWith("inv-") || c.keywords.includes(q));
  }, [query, detection, recent, attack, prefs, setPref, router, onClose, start]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- keep selection in range
    setActive((a) => Math.min(a, Math.max(0, commands.length - 1)));
  }, [commands.length]);

  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  const groups: { name: string; items: { cmd: Command; index: number }[] }[] = [];
  commands.forEach((cmd, index) => {
    const g = groups.find((x) => x.name === cmd.group);
    if (g) g.items.push({ cmd, index });
    else groups.push({ name: cmd.group, items: [{ cmd, index }] });
  });

  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-start justify-center px-4 pt-[12vh]" onKeyDown={(e) => e.key === "Escape" && onClose()}>
      <div className="absolute inset-0 animate-fade bg-black/60" onClick={onClose} aria-hidden />
      <div role="dialog" aria-modal="true" aria-label="Command palette" className="panel panel-ticks relative flex max-h-[68vh] w-full max-w-[640px] animate-rise flex-col overflow-hidden shadow-[0_32px_100px_rgba(0,0,0,0.7)]">
        <div className="flex items-center gap-3 border-b border-line-1 px-4">
          <Search size={15} className="text-fg-3" aria-hidden />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setActive((a) => Math.min(commands.length - 1, a + 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setActive((a) => Math.max(0, a - 1));
              } else if (e.key === "Enter") {
                e.preventDefault();
                commands[active]?.run();
              }
            }}
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={commands[active] ? `cmd-${commands[active].id}` : undefined}
            spellCheck={false}
            autoComplete="off"
            placeholder="Paste an observable, search investigations, ATT&CK, or jump anywhere…"
            className="h-[50px] min-w-0 flex-1 bg-transparent text-[15px] text-fg-1 outline-none placeholder:text-fg-4"
          />
          {loadingAttack && <Loader2 size={14} className="animate-spin text-fg-4" aria-hidden />}
          <Kbd>esc</Kbd>
        </div>
        <div ref={listRef} id={listId} role="listbox" className="min-h-0 flex-1 overflow-y-auto p-1.5">
          {!commands.length && <div className="px-3 py-8 text-center text-sm text-fg-3">No matches. Paste an IP, domain, URL, hash, CVE, ASN or email to investigate it.</div>}
          {groups.map((g) => (
            <div key={g.name} role="group" aria-label={g.name} className="mb-1">
              <div className="label px-2.5 pt-2 pb-1.5">{g.name}</div>
              {g.items.map(({ cmd, index }) => (
                <div
                  key={cmd.id}
                  id={`cmd-${cmd.id}`}
                  role="option"
                  aria-selected={index === active}
                  data-index={index}
                  onMouseMove={() => setActive(index)}
                  onClick={() => cmd.run()}
                  className={cx("flex h-[36px] cursor-pointer items-center gap-3 rounded-[2px] px-2.5 text-sm", index === active ? "bg-ink-3 text-fg-1" : "text-fg-2")}
                >
                  <span className={cx("grid w-[18px] place-items-center", index === active ? "text-fg-1" : "text-fg-3")}>{cmd.icon}</span>
                  <span className="min-w-0 flex-1 truncate">{cmd.label}</span>
                  {cmd.hint && <span className="shrink-0">{cmd.hint}</span>}
                  {index === active && <ArrowRight size={13} className="shrink-0 text-fg-3" aria-hidden />}
                </div>
              ))}
            </div>
          ))}
        </div>
        <div className="flex items-center gap-4 border-t border-line-1 px-4 py-2 text-2xs text-fg-4">
          <span className="flex items-center gap-1.5">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd> navigate
          </span>
          <span className="flex items-center gap-1.5">
            <Kbd>↵</Kbd> run
          </span>
          <span className="ml-auto">Detection runs server-side against the Public Suffix List</span>
        </div>
      </div>
    </div>,
    document.body
  );
}
