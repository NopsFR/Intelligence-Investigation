import { Activity, Crosshair, LayoutDashboard, Library, ListTree, Settings2, Wrench, type LucideIcon } from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  shortcut?: string;
  match?: (path: string) => boolean;
}

export const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: "Operate",
    items: [
      { href: "/", label: "Dashboard", icon: LayoutDashboard, shortcut: "G D", match: (p) => p === "/" },
      { href: "/investigations", label: "Investigations", icon: ListTree, shortcut: "G I", match: (p) => p.startsWith("/investigations") },
    ],
  },
  {
    group: "Intelligence",
    items: [
      { href: "/ioc", label: "IOC library", icon: Library, shortcut: "G L" },
      { href: "/attack", label: "ATT&CK", icon: Crosshair, shortcut: "G A" },
    ],
  },
  {
    group: "Platform",
    items: [
      { href: "/observatory", label: "API Observatory", icon: Activity, shortcut: "G O" },
      { href: "/toolbox", label: "Toolbox", icon: Wrench, shortcut: "G T" },
      { href: "/settings", label: "Settings", icon: Settings2, shortcut: "G S" },
    ],
  },
];

export function isActive(item: NavItem, path: string): boolean {
  return item.match ? item.match(path) : path === item.href || path.startsWith(`${item.href}/`);
}
