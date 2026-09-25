import { Suspense } from "react";
import { settingsData } from "@/lib/db/settings";
import { isOperator } from "@/lib/server/api";
import { Page } from "@/components/shell/Page";
import { Settings } from "@/components/settings/Settings";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Settings" };

export default async function SettingsPage() {
  const data = await settingsData(await isOperator());
  return (
    <Page>
      <PageHeader eyebrow="Platform" title="Settings" description="Provider credentials, security posture, database state, appearance and developer diagnostics. Secrets are never displayed." />
      <Suspense>
        <Settings data={data} />
      </Suspense>
    </Page>
  );
}
