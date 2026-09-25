import { ViewTransition, type ReactNode } from "react";
import { cx } from "@/lib/client/cx";

/** Page frame: consistent gutters plus the enter/exit view transition (layouts never fire them). */
export function Page({ children, width = "wide", className }: { children: ReactNode; width?: "narrow" | "wide" | "full"; className?: string }) {
  return (
    <ViewTransition enter="page" exit="page" default="none">
      <div className={cx("mx-auto w-full px-4 pt-6 sm:px-6 lg:px-8", width === "narrow" ? "max-w-[980px]" : width === "wide" ? "max-w-[1480px]" : "max-w-none", className)}>{children}</div>
    </ViewTransition>
  );
}
