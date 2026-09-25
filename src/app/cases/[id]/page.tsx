import { notFound } from "next/navigation";
import { getCase } from "@/lib/db/cases";
import { Page } from "@/components/shell/Page";
import { CaseWorkspace, type CaseRecordInput } from "@/components/cases/CaseWorkspace";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const record = await getCase(id).catch(() => null);
  return { title: record ? record.title : "Case" };
}

export default async function CasePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const record = await getCase(id).catch(() => null);
  if (!record) notFound();
  return (
    <Page>
      <CaseWorkspace initial={record as unknown as CaseRecordInput} />
    </Page>
  );
}
