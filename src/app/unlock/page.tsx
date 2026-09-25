import { Suspense } from "react";
import { UnlockForm } from "@/components/settings/UnlockForm";
import { Mark } from "@/components/shell/Logo";

export const metadata = { title: "Unlock" };

export default function UnlockPage() {
  return (
    <div className="grid min-h-[calc(100dvh-var(--topbar-h)-var(--statusbar-h)-48px)] place-items-center px-4">
      <div className="panel panel-ticks w-full max-w-[400px] p-6">
        <Mark size={24} className="mb-4 text-fg-1" />
        <h1 className="display text-xl text-fg-1">Private deployment</h1>
        <p className="mt-1 mb-5 text-sm text-fg-3">This instance requires an operator session. Enter the operator token configured on the server.</p>
        <Suspense>
          <UnlockForm />
        </Suspense>
      </div>
    </div>
  );
}
