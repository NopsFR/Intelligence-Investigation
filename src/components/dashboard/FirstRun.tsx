"use client";

import { ArrowRight } from "lucide-react";
import { useInvestigate } from "@/lib/client/investigate";
import type { ObservableType } from "@/lib/core/types";
import { TypeTag } from "@/components/ui/badges";

// Real, well-known observables that exercise different parts of the engine.
const EXAMPLES: { value: string; type: ObservableType; why: string }[] = [
  { value: "8.8.8.8", type: "IPV4", why: "Public resolver — reputation, routing, reverse DNS" },
  { value: "example.com", type: "DOMAIN", why: "DNS, email authentication, registration" },
  { value: "CVE-2021-44228", type: "CVE", why: "Log4Shell — CVSS, KEV, EPSS, affected products" },
  { value: "AS13335", type: "ASN", why: "Cloudflare — routing and registry data" },
  { value: "44d88612fea8a8f36de82e1278abb02f", type: "MD5", why: "EICAR test file — malware databases" },
];

export function ExampleObservables() {
  const { start, pending } = useInvestigate();
  return (
    <ul className="divide-y divide-line-1 border-y border-line-1">
      {EXAMPLES.map((e) => (
        <li key={e.value}>
          <button type="button" disabled={pending} onClick={() => void start(e.value, "QUICK")} className="group flex w-full items-center gap-3 px-1 py-2.5 text-left transition-colors hover:bg-ink-2">
            <TypeTag type={e.type} className="w-[52px] justify-center" />
            <span className="mono min-w-0 flex-1 truncate text-[12.5px] text-fg-1">{e.value}</span>
            <span className="hidden text-xs text-fg-3 md:block">{e.why}</span>
            <ArrowRight size={13} className="text-fg-4 transition-transform group-hover:translate-x-0.5 group-hover:text-fg-1" aria-hidden />
          </button>
        </li>
      ))}
    </ul>
  );
}
