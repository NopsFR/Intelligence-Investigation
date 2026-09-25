import { Page } from "@/components/shell/Page";
import { CodeSecurity } from "@/components/analysis/code/CodeSecurity";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Code security" };

export default function CodeSecurityPage() {
  return (
    <Page>
      <PageHeader
        eyebrow="Analysis"
        title="Code security"
        description="Static checks over a local project folder: dependency advisories from OSV.dev, hardcoded secrets, and Dockerfile / compose / Kubernetes / Terraform / GitHub Actions misconfiguration. Files stay in your browser."
      />
      <CodeSecurity />
    </Page>
  );
}
