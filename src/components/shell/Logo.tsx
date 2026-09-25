import { cx } from "@/lib/client/cx";

/** NOPS mark: an aperture square with the signal notch. */
export function Mark({ size = 20, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 20 20" className={className} aria-hidden>
      <rect x="0.75" y="0.75" width="18.5" height="18.5" rx="1.5" fill="none" stroke="currentColor" strokeOpacity="0.55" strokeWidth="1.5" />
      <path d="M5 15V5l10 10V5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="square" />
      <rect x="13" y="1.6" width="5.4" height="5.4" fill="var(--color-signal)" />
    </svg>
  );
}

export function Wordmark({ collapsed = false, className }: { collapsed?: boolean; className?: string }) {
  return (
    <span className={cx("flex items-center gap-2.5 text-fg-1", className)}>
      <Mark size={20} />
      {!collapsed && (
        <span className="flex flex-col leading-none">
          <span className="text-[13px] font-bold tracking-[0.22em]" style={{ fontStretch: "88%" }}>
            NOPS
          </span>
          <span className="mt-[3px] text-[9px] font-semibold tracking-[0.16em] text-fg-3" style={{ fontStretch: "75%" }}>
            CYBER INTELLIGENCE
          </span>
        </span>
      )}
    </span>
  );
}
