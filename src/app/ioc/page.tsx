import { listIocs } from "@/lib/db/ioc";
import { Page } from "@/components/shell/Page";
import { IocLibrary } from "@/components/ioc/IocLibrary";
import { ErrorNote, PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "IOC library" };

export default async function IocPage() {
  let items: Awaited<ReturnType<typeof listIocs>> | null = null;
  let error: string | null = null;
  try {
    items = await listIocs();
  } catch (e) {
    error = (e as Error).message.split("\n")[0];
  }
  return (
    <Page>
      <PageHeader eyebrow="Intelligence" title="IOC library" description="Indicators you are tracking, with their latest investigation. Export as CSV, JSON or a STIX 2.1 bundle." />
      {items ? <IocLibrary initial={items} /> : <ErrorNote title="The database is not reachable">{error}</ErrorNote>}
    </Page>
  );
}
