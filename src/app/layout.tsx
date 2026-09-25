import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import { headers } from "next/headers";
import { AppShell } from "@/components/shell/AppShell";
import { ToastProvider } from "@/components/ui/overlays";
import { CatalogProvider } from "@/lib/client/catalog";
import { PREFS_BOOT_SCRIPT, PrefsProvider } from "@/lib/client/prefs";
import { SessionProvider } from "@/lib/client/session";
import { providerCatalog } from "@/lib/providers/catalog";
import { isOperator } from "@/lib/server/api";
import { operatorConfigured } from "@/lib/server/session";
import "./globals.css";

const archivo = localFont({
  src: "../../node_modules/@fontsource-variable/archivo/files/archivo-latin-standard-normal.woff2",
  variable: "--font-archivo",
  weight: "100 900",
  display: "swap",
  declarations: [{ prop: "font-stretch", value: "62% 125%" }],
});

const plexMono = localFont({
  src: [
    { path: "../../node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2", weight: "400" },
    { path: "../../node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-500-normal.woff2", weight: "500" },
    { path: "../../node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-600-normal.woff2", weight: "600" },
  ],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "NOPS / Cyber Intelligence", template: "%s · NOPS" },
  description: "Evidence-based threat intelligence and investigation platform.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#08090a",
  colorScheme: "dark",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  const operator = await isOperator();
  return (
    <html lang="en" className={`${archivo.variable} ${plexMono.variable}`} suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: PREFS_BOOT_SCRIPT }} />
      </head>
      <body>
        <PrefsProvider>
          <SessionProvider initial={{ operator, configured: operatorConfigured(), privateMode: process.env.NOPS_PRIVATE === "1" }}>
            <CatalogProvider providers={providerCatalog()}>
              <ToastProvider>
                <AppShell>{children}</AppShell>
              </ToastProvider>
            </CatalogProvider>
          </SessionProvider>
        </PrefsProvider>
      </body>
    </html>
  );
}
