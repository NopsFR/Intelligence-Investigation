"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { Menu, X } from "lucide-react";

const LINKS = [
  { href: "/", label: "Dashboard" },
  { href: "/investigate", label: "Investigate" },
  { href: "/history", label: "History" },
  { href: "/ioc-library", label: "IOC Library" },
  { href: "/attack", label: "ATT&CK" },
  { href: "/toolbox", label: "Toolbox" },
  { href: "/observatory", label: "Observatory" },
  { href: "/settings", label: "Settings" },
];

export function Nav() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <nav className="sticky top-0 z-40 border-b border-[var(--nops-border)] bg-[var(--nops-bg)]/95 backdrop-blur">
      <div className="mx-auto flex max-w-[1400px] items-center justify-between px-4 py-3 md:px-6">
        <Link href="/" className="flex items-center gap-2 shrink-0" aria-label="NOPS home">
          <span className="inline-block h-2 w-2 rounded-full bg-[var(--nops-red)]" aria-hidden />
          <span className="font-mono text-sm tracking-[0.18em] text-[var(--nops-text)]">
            NOPS<span className="text-[var(--nops-text-faint)]">/</span>
            <span className="text-[var(--nops-text-dim)]"> CYBER INTELLIGENCE</span>
          </span>
        </Link>

        <button
          className="md:hidden p-2 text-[var(--nops-text-dim)]"
          onClick={() => setOpen((v) => !v)}
          aria-label={open ? "Close menu" : "Open menu"}
          aria-expanded={open}
        >
          {open ? <X size={18} /> : <Menu size={18} />}
        </button>

        <ul className="hidden md:flex items-center gap-1 font-mono text-[13px]">
          {LINKS.map((link) => {
            const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
            return (
              <li key={link.href}>
                <Link
                  href={link.href}
                  className={`block rounded px-3 py-1.5 transition-colors ${
                    active
                      ? "text-[var(--nops-text)] bg-[var(--nops-bg-panel)] border border-[var(--nops-border-strong)]"
                      : "text-[var(--nops-text-dim)] hover:text-[var(--nops-text)] border border-transparent"
                  }`}
                >
                  {link.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </div>

      {open && (
        <ul className="md:hidden border-t border-[var(--nops-border)] font-mono text-sm">
          {LINKS.map((link) => {
            const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
            return (
              <li key={link.href}>
                <Link
                  href={link.href}
                  onClick={() => setOpen(false)}
                  className={`block px-5 py-3 border-b border-[var(--nops-border)] ${
                    active ? "text-[var(--nops-text)] bg-[var(--nops-bg-panel)]" : "text-[var(--nops-text-dim)]"
                  }`}
                >
                  {link.label}
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </nav>
  );
}
