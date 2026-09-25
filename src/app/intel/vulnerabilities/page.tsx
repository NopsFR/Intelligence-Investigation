import { Page } from "@/components/shell/Page";
import { Vulnerabilities } from "@/components/intel/Vulnerabilities";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Vulnerabilities" };

export default function VulnerabilitiesPage() {
  return (
    <Page>
      <PageHeader eyebrow="Intelligence" title="Vulnerabilities" description="CISA's Known Exploited Vulnerabilities catalogue, recently published CVEs from NVD, and the highest-probability EPSS exploit predictions — each with its source and fetch time." />
      <Vulnerabilities />
    </Page>
  );
}
