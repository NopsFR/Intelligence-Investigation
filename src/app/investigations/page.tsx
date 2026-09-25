import { Suspense } from "react";
import { listInvestigations } from "@/lib/db/investigations";
import { listSchema } from "@/lib/server/schemas";
import { Page } from "@/components/shell/Page";
import { HistoryView } from "@/components/investigations/HistoryView";
import { ErrorNote, PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Investigations" };

export default async function InvestigationsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const parsed = listSchema.safeParse(Object.fromEntries(Object.entries(sp).filter(([, v]) => typeof v === "string")));
  let initial: Awaited<ReturnType<typeof listInvestigations>> | null = null;
  let error: string | null = null;
  try {
    initial = await listInvestigations({ ...(parsed.success ? parsed.data : {}), limit: 40 } as Parameters<typeof listInvestigations>[0]);
  } catch (e) {
    error = (e as Error).message.split("\n")[0];
  }
  return (
    <Page>
      <PageHeader eyebrow="Operate" title="Investigations" description="Every investigation is kept with its full evidence trail. Select two to compare how an observable changed." />
      {initial ? (
        <Suspense>
          <HistoryView initial={initial} />
        </Suspense>
      ) : (
        <ErrorNote title="The database is not reachable">{error}</ErrorNote>
      )}
    </Page>
  );
}
