import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { getInvestigation, investigationHistory } from "@/lib/db/investigations";
import { Page } from "@/components/shell/Page";
import { Workspace } from "@/components/investigation/Workspace";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  const inv = /^[a-z0-9]{8,40}$/i.test(id) ? await getInvestigation(id).catch(() => null) : null;
  return { title: inv ? inv.normalizedObservable : "Investigation" };
}

export default async function InvestigationPage({ params }: Props) {
  const { id } = await params;
  if (!/^[a-z0-9]{8,40}$/i.test(id)) notFound();
  const inv = await getInvestigation(id);
  if (!inv) notFound();
  const history = await investigationHistory(inv.normalizedObservable, inv.observableType, inv.id);
  return (
    <Page className="relative">
      <Suspense>
        <Workspace initial={inv} history={history} />
      </Suspense>
    </Page>
  );
}
