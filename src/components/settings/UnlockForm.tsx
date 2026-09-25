"use client";

import { Loader2, Unlock } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import type { ApiClientError } from "@/lib/client/api";
import { useSession } from "@/lib/client/session";

export function UnlockForm() {
  const { unlock } = useSession();
  const router = useRouter();
  const next = useSearchParams().get("next");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          await unlock(token);
          router.replace(next && next.startsWith("/") && !next.startsWith("//") ? next : "/");
          router.refresh();
        } catch (err) {
          setError((err as ApiClientError).message);
          setBusy(false);
        }
      }}
    >
      <label htmlFor="token" className="text-xs text-fg-3">
        Operator token
      </label>
      <input id="token" type="password" autoComplete="current-password" autoFocus className="input mono text-[12px]" value={token} onChange={(e) => setToken(e.target.value)} />
      {error && <p className="text-xs text-err">{error}</p>}
      <button type="submit" className="btn btn-primary mt-2" disabled={busy || !token}>
        {busy ? <Loader2 size={13} className="animate-spin" /> : <Unlock size={13} />} Unlock
      </button>
    </form>
  );
}
