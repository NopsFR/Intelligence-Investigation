import { observatorySnapshot } from "@/lib/db/health";
import { Page } from "@/components/shell/Page";
import { Observatory } from "@/components/observatory/Observatory";
import { ErrorNote, PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "API Observatory" };

export default async function ObservatoryPage() {
  let snapshot: Awaited<ReturnType<typeof observatorySnapshot>> | null = null;
  let error: string | null = null;
  try {
    snapshot = await observatorySnapshot();
  } catch (e) {
    error = (e as Error).message.split("\n")[0];
  }
  return (
    <Page>
      <PageHeader
        eyebrow="Platform"
        title="API Observatory"
        description="Every intelligence source, its authentication state and its measured behaviour. Tests perform a real request with a known observable; usage figures come from actual investigations."
      />
      {snapshot ? <Observatory initial={snapshot} /> : <ErrorNote title="The database is not reachable">{error}</ErrorNote>}
    </Page>
  );
}
