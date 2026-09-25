# NOPS / Cyber Intelligence

An evidence-based cybersecurity intelligence and investigation workspace. Enter an IP, domain, URL,
hash, CVE, or ASN — NOPS detects its type, queries the providers that support it, runs native DNS,
TLS, and header analysis where relevant, and surfaces findings with their evidence and source. It
never fabricates a result: if a provider is unconfigured, rate-limited, or times out, that is what
you see.

## What it is not

This is not a chatbot, not an "AI security assistant," and not a dashboard of invented threat
scores. There is no LLM in the request path. Every number and every finding traces back to a named
provider and a timestamp.

## Features

- **Observable detection** — IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256, CVE IDs, and ASNs are
  detected automatically from a single search box.
- **Quick Scan vs. Deep Investigation** — a fast pass over high-signal sources, or the full
  provider set plus native DNS/TLS/header analysis.
- **Provider architecture** — every external source is an isolated adapter behind a common
  interface (`investigate()`, `healthCheck()`, `isConfigured()`). One provider failing never takes
  down the investigation; the overall status is reported as `PARTIAL`, not `FAILED`.
- **Native intelligence** — SPF/DMARC/MTA-STS/TLS-RPT/BIMI record inspection, direct TLS
  certificate inspection, and security-header inspection, all implemented locally (no third-party
  API needed).
- **Findings engine** — every finding carries a severity, evidence string, source, and timestamp.
  No arbitrary "risk score."
- **Correlation & relationship graph** — an interactive graph (React Flow) of only the
  provider-evidenced relationships for an observable (DNS resolutions, certificate SANs, IOC
  associations). Every edge is clickable and shows its source.
- **Persistence** — investigations, findings, relationships, and provider results are stored via
  Prisma/Postgres.
- **API Observatory** — live "Test connection" against every configured provider. No key, token,
  or Authorization header is ever rendered in the UI.
- **Toolbox** — standalone DNS lookup, RDAP lookup, certificate transparency search, TLS
  inspection, security header inspection, and URL parsing.
- **IOC Library** — a simple, real, database-backed store for tracked indicators with tags and
  notes.
- **ATT&CK Explorer** — a curated, vendored subset of the MITRE ATT&CK Enterprise matrix
  (tactics → techniques → sub-techniques), searchable and filterable.
- **Reporting** — export any investigation as JSON, Markdown, or CSV, or print to PDF via the
  browser's native print dialog (a dedicated print stylesheet hides navigation chrome).

## Architecture

```
src/
  app/                    Next.js App Router pages and API route handlers
  components/             Shared UI (nav, badges, findings list, graph, export bar, ...)
  lib/
    observables/          Detection, normalization, URL parsing
    providers/             Provider interface, registry, and every adapter
    dns/                   DNS-over-HTTPS resolution + email security (SPF/DMARC/...)
    tls/                   Direct TLS certificate inspection
    headers/               Security header inspection
    validation/            Zod schemas — every third-party response is validated
    security/              SSRF protection, safe fetch wrapper, rate limiting
    investigation/         The orchestrator (detect → select providers → run → correlate)
    findings/              Findings aggregation
    correlation/           Relationship graph construction
    db/                    Prisma client + persistence helpers
    reporting/             JSON/Markdown/CSV export
    attack/                Vendored ATT&CK data
prisma/                    Database schema and migrations
e2e/                       Playwright end-to-end tests
```

Nothing calls a third-party API directly from a React component. Every provider is an adapter
implementing the same `Provider` interface, registered once in `src/lib/providers/registry.ts`,
and invoked only from the server-side orchestrator or API routes.

## Providers

| Provider | Observable types | Auth | Notes |
|---|---|---|---|
| RDAP | Domain, IP, ASN | None | Registration data via [rdap.org](https://rdap.org) |
| crt.sh | Domain | None | Certificate Transparency search |
| Cloudflare DNS | Domain | None | DNS-over-HTTPS |
| Google DNS | Domain | None | DNS-over-HTTPS (used as fallback and for cross-checking) |
| NVD | CVE | Optional key raises rate limit | CVE description, CVSS, CWE |
| CISA KEV | CVE | None | Known Exploited Vulnerabilities catalog |
| AbuseIPDB | IPv4, IPv6 | Free registration | Abuse confidence score |
| VirusTotal | IP, domain, URL, hash | Free registration | Multi-engine reputation (rate-limited) |
| ThreatFox (abuse.ch) | IP, domain, URL, hash | Free `Auth-Key` | IOC intelligence |
| URLhaus (abuse.ch) | URL, domain, IP | Free `Auth-Key` | Malicious URL / payload tracking |
| MalwareBazaar (abuse.ch) | MD5, SHA1, SHA256 | Free `Auth-Key` | Malware sample metadata |

Native, locally-implemented capabilities (no external API): email security record inspection
(SPF/DMARC/MTA-STS/TLS-RPT/BIMI), TLS certificate inspection, security header inspection, and URL
structure parsing.

**abuse.ch requires a free `Auth-Key`** for ThreatFox, URLhaus, and MalwareBazaar as of their 2025
policy change — register once at [auth.abuse.ch](https://auth.abuse.ch/) and the same key works
across all three.

Every provider that is not configured shows **"Not configured"** — it is skipped, not faked. See
the API Observatory page in the running app for live status, and `.env.example` for exactly which
variables enable which provider.

## Getting started

```bash
npm install
cp .env.example .env.local     # set DATABASE_URL to a Postgres connection string
npm run db:migrate             # applies the schema
npm run dev
```

Open http://localhost:3000.

### Database

Postgres is required in every environment — any provider works (a local Postgres install, Docker,
Supabase, Neon, RDS, ...). Point `DATABASE_URL` at it and run `npm run db:migrate`. For a
serverless deployment (Vercel), use a connection-pooled URL (e.g. Supabase's "Transaction pooler"
on port 6543) so functions don't exhaust the database's direct connection limit.

### Scripts

```bash
npm run dev          # start the dev server
npm run build        # production build
npm run start        # run the production build
npm run lint         # ESLint
npm run test         # Vitest unit tests
npm run test:e2e     # Playwright end-to-end tests (requires the app running or will start one)
npm run db:migrate   # apply Prisma migrations
npm run db:studio    # browse the database with Prisma Studio
```

## Security model

- **No secrets in the browser.** Every provider key lives in server-only environment variables and
  is read only inside server-side adapters (`src/lib/providers/*`) and API routes. The Settings and
  API Observatory pages show masked configuration state and test-connection results only.
- **SSRF protection.** `src/lib/security/ssrf.ts` resolves and validates every destination hostname
  before connecting, rejecting loopback, private (RFC1918), link-local, CGNAT, and cloud-metadata
  address ranges. `src/lib/security/safeFetch.ts` re-validates the destination on every redirect
  hop, bounds redirects to 5, enforces a response size cap, and enforces a request timeout. This
  applies to provider calls and, critically, to the Toolbox's user-supplied URL/hostname inputs
  (TLS inspection, header inspection).
- **Input validation.** Every API route validates its request body with Zod
  (`src/lib/validation/schemas.ts`) before touching the database or an external provider.
- **Output validation.** Every provider adapter validates the third-party response shape with Zod
  before treating it as trustworthy data; a malformed or unexpected shape is reported as
  `Invalid provider response`, never silently coerced.
- **Rate limiting.** A minimal in-memory limiter (`src/lib/security/rateLimit.ts`) protects the
  investigation, toolbox, and observatory-test endpoints. Suitable for a single instance; back it
  with shared storage for a multi-instance deployment.
- **Security headers & CSP** are set application-wide in `next.config.ts` (CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- **No secrets persisted.** Raw provider payloads are redacted for key/token/secret-shaped fields
  before being stored, and no request headers are ever persisted.

## Testing

- **Unit tests** (Vitest) cover observable detection/normalization, Zod validation, SSRF IP-range
  blocking, error classification, the findings and correlation engines, and full provider-adapter
  behavior (success, 401, 429, 500, malformed JSON, missing fields, network failure) with mocked
  `fetch`/DNS — no live network calls.
- **End-to-end tests** (Playwright, desktop + mobile viewport) cover navigation, keyboard
  accessibility, observable detection UI states (valid/invalid/empty), history filtering/empty
  state, and the IOC Library's full add/remove flow against the real local database.

Run `npm run test` and `npm run test:e2e`.

## Known limitations

- Deep DKIM verification requires a known selector, which cannot be derived from DNS alone; DKIM
  is not currently checked (SPF, DMARC, MTA-STS, TLS-RPT, and BIMI are).
- The ATT&CK Explorer ships a curated, hand-picked subset of the Enterprise matrix rather than the
  full STIX dataset, to keep the vendored payload small.
- Certificate Transparency enumeration (crt.sh) is not an exhaustive subdomain list — only names
  covered by a logged, issued certificate appear.
- PDF export uses the browser's native print dialog rather than a server-side PDF renderer.
- The in-memory rate limiter and provider health cache are per-instance; a multi-node deployment
  should back these with shared storage (Redis or similar).
- This project intentionally does not implement authentication for v1 — see the architecture
  notes if you need to add it before exposing this publicly.

## Deployment

The app is a standard Next.js application (Node.js runtime, no edge-only assumptions) and deploys
to Vercel or any Node host. Set `DATABASE_URL` and whichever provider keys you have in the
platform's environment variable settings — never commit `.env.local`. Point `DATABASE_URL` at a
managed Postgres instance in production and run `prisma migrate deploy` as part of your deploy
step.

## Methodology

This tool represents what the configured providers returned at the time of investigation. Absence
of an indicator does not prove absence of malicious activity. Provider availability, rate limits,
coverage, and data freshness all affect results — which is why every finding and provider result
carries an explicit timestamp and source.
