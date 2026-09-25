import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import { Nav } from "@/components/Nav";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const mono = JetBrains_Mono({
  variable: "--font-mono-tech",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "NOPS / Cyber Intelligence",
  description:
    "An evidence-based cybersecurity intelligence and investigation workspace for IPs, domains, URLs, hashes, and CVEs.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable} h-full`}>
      <body className="min-h-full flex flex-col bg-[var(--nops-bg)] text-[var(--nops-text)]">
        <Nav />
        <main className="flex-1">{children}</main>
        <footer className="border-t border-[var(--nops-border)] py-6">
          <div className="mx-auto max-w-[1400px] px-4 md:px-6 font-mono text-[11px] text-[var(--nops-text-faint)] flex flex-wrap gap-x-4 gap-y-1 justify-between">
            <span>NOPS / CYBER INTELLIGENCE</span>
            <span>Investigations reflect provider data at time of query. Absence of an indicator does not prove absence of activity.</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
