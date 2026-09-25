"use client";

import { RotateCw } from "lucide-react";

export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="mx-auto w-full max-w-[980px] px-4 pt-10 sm:px-6">
      <div role="alert" className="panel panel-ticks p-8">
        <div className="mono mb-2 text-[12px] text-err">Error{error.digest ? ` · ${error.digest}` : ""}</div>
        <h1 className="display text-xl text-fg-1">This view failed to load</h1>
        <p className="mt-1.5 text-sm text-fg-3">The rest of the application is unaffected. If the database is unreachable, pages that read history will fail until it returns; live status is shown in the bar at the bottom.</p>
        <button type="button" className="btn btn-sm mt-5" onClick={reset}>
          <RotateCw size={12} /> Try again
        </button>
      </div>
    </div>
  );
}
