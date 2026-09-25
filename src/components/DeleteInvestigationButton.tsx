"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Trash2 } from "lucide-react";

export function DeleteInvestigationButton({ id }: { id: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  return (
    <button
      aria-label="Delete investigation"
      disabled={busy}
      onClick={async (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!confirm("Delete this investigation? This cannot be undone.")) return;
        setBusy(true);
        await fetch(`/api/investigate/${id}`, { method: "DELETE" });
        router.refresh();
      }}
      className="p-1.5 text-[var(--nops-text-faint)] hover:text-[var(--nops-red)] transition-colors disabled:opacity-40"
    >
      <Trash2 size={14} />
    </button>
  );
}
