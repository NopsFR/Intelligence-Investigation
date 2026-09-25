import { Page } from "@/components/shell/Page";
import { WebSecurity } from "@/components/analysis/web/WebSecurity";
import { PageHeader } from "@/components/ui/primitives";

export const metadata = { title: "Web security" };

export default function WebSecurityPage() {
  return (
    <Page>
      <PageHeader eyebrow="Analysis" title="Web security" description="Headers, cookies, TLS, CORS, security.txt, robots.txt, sitemap.xml and technology indicators for a URL you are authorized to test. Purely observational — no exploitation." />
      <WebSecurity />
    </Page>
  );
}
