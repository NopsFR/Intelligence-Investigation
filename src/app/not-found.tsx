import Link from "next/link";
import { Page } from "@/components/shell/Page";

export default function NotFound() {
  return (
    <Page width="narrow">
      <div className="panel panel-ticks mt-10 p-8">
        <div className="mono mb-2 text-[12px] text-fg-4">404</div>
        <h1 className="display text-xl text-fg-1">Nothing here</h1>
        <p className="mt-1.5 text-sm text-fg-3">The page or record does not exist — it may have been deleted. Paste an observable in the command bar to start a new investigation.</p>
        <div className="mt-5 flex gap-2">
          <Link href="/" className="btn btn-sm">
            Dashboard
          </Link>
          <Link href="/investigations" className="btn btn-ghost btn-sm">
            Investigations
          </Link>
        </div>
      </div>
    </Page>
  );
}
