import Link from "next/link";
import type { ReactNode } from "react";

const LINK = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g;

/** Renders ATT&CK markdown-ish text safely: links only, citations stripped, ATT&CK links kept in-app. */
export function AttackText({ text, className }: { text: string; className?: string }) {
  const clean = text.replace(/\(Citation:[^)]*\)/g, "").replace(/<code>(.*?)<\/code>/g, "`$1`").trim();
  return (
    <div className={className}>
      {clean.split(/\n{2,}/).map((para, i) => {
        const out: ReactNode[] = [];
        let last = 0;
        for (const m of para.matchAll(LINK)) {
          out.push(para.slice(last, m.index));
          const id = m[2].match(/attack\.mitre\.org\/(?:techniques|groups|software|campaigns|mitigations|tactics)\/([A-Z]+\d{4})(?:\/(\d{3}))?/);
          out.push(
            id ? (
              <Link key={`${i}-${m.index}`} href={`/attack/${id[1]}${id[2] ? `.${id[2]}` : ""}`} className="link">
                {m[1]}
              </Link>
            ) : (
              <a key={`${i}-${m.index}`} href={m[2]} target="_blank" rel="noopener noreferrer nofollow" className="link">
                {m[1]}
              </a>
            )
          );
          last = (m.index ?? 0) + m[0].length;
        }
        out.push(para.slice(last));
        return (
          <p key={i} className="mb-2.5 last:mb-0">
            {out}
          </p>
        );
      })}
    </div>
  );
}
