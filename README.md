# NOPS / Cyber Intelligence

An evidence-based threat-intelligence and investigation workstation. Paste an IP address, domain, URL, email address, file hash, CVE, ASN or certificate fingerprint; NOPS works out what it is, queries the sources that can say something about it, and turns their answers into findings that cite their evidence and their source.

There is no "threat score". Every finding states what was found, why it matters, the evidence, which source reported it and when. A source that answers with nothing is recorded as *no result*; a source without credentials is *not configured* and is never called; a timeout, rate limit or malformed response is shown as exactly that.

## What it does

- **Detection and normalisation** — type detection with refanging (`hxxp`, `[.]`, `[at]`), IPv6 canonicalisation, IDN/punycode handling, Public Suffix List awareness, port stripping and explicit alternatives (e.g. a SHA-256 that could be a certificate fingerprint).
- **Investigation engine** — builds a dependency-ordered plan of sources for the observable, runs them in parallel with bounded concurrency, persists each result as it lands, and streams progress to the workspace. Partial failures never block the rest.
- **Two modes**
  - *Quick scan* — passive only: intelligence feeds, reputation, registration, routing and DNS. Nothing contacts the target.
  - *Deep investigation* — everything, plus direct TLS handshakes, HTTP requests and mail-policy fetches against the target, DNSSEC checks, certificate-transparency history and DKIM selector probing. Requires an operator session.
- **Findings** — rule-based, each with severity, rationale, evidence, structured evidence data, affected observable, remediation and references where the source provides them. Findings link to the source's normalised result and its stored raw response.
- **Correlation** — cross-source reasoning: corroboration by *independent organisations* (abuse.ch's feeds count once), single-source detections, contradictions (e.g. flagged by one source, known-good in NSRL/GreyNoise RIOT), a newly registered domain collecting credentials, and CVSS source selection for CVEs (NVD primary → CNA → CISA ADP).
- **Evidence graph** — every edge is a relationship reported by a source, with its evidence and provenance. Hover to trace a neighbourhood, select to read evidence and pivot, focus mode, entity-type filters, bounded to the 120 entities nearest the observable.
- **MITRE ATT&CK** — Enterprise v19.2 bundled locally: full matrix, search, entity pages with procedures, and mapping of malware families named by sources to ATT&CK software and techniques (groups are shown as documented users, never as attribution).
- **API Observatory** — per-source authentication state, real connection tests, latency history, 24 h usage from actual investigations, local request budgets and last error.
- **History and comparison**, **IOC library** (text extraction, tags, CSV/JSON/STIX 2.1 export), **exports** (Markdown report with defanged observables, findings CSV, full JSON, printable report), and a **toolbox** (defang/refang, extractor, live DoH lookup, IPv4 subnet calculator, CVSS vector decoder, Base64/URL/epoch decoding).

## Sources

| Source | Contributes | Credentials | Modes |
|---|---|---|---|
| **Native analysers** | | | |
| Address classification | IANA special-purpose ranges (private, CGNAT, link-local, documentation, NAT64…) | none | quick + deep |
| Hostname structure | Registrable domain, public suffix, subdomain depth, shared-platform suffixes, punycode/mixed-script | none | quick + deep |
| URL structure | Userinfo tricks, IP hosts, executable paths, redirect parameters, non-standard ports | none | quick + deep |
| DNS resolution | A/AAAA/CNAME/NS/MX/TXT/CAA/SOA via Cloudflare DoH, cross-checked against Google DoH and DNS.SB (RFC 8484 wire format); dangling CNAMEs, private answers, resolver disagreement | none | quick + deep |
| DNSSEC | DS at the parent, DNSKEY, validation via the AD bit, bogus/legacy algorithms | none | deep |
| Reverse DNS | PTR with forward confirmation | none | quick + deep |
| Email security | SPF (recursive lookup counting), DMARC (org-domain fallback), MTA-STS (policy fetched in deep mode), TLS-RPT, BIMI, DKIM common selectors (deep) | none | quick + deep |
| TLS & certificate | Direct handshake: chain, validity, hostname match, key strength, protocol, legacy TLS 1.0/1.1 acceptance | none | deep (contacts target) |
| HTTP response & headers | Redirect chain, final destination, content type, page title, HTTP→HTTPS upgrade, HSTS/CSP/framing/CORS/cookies, credential forms posting off-site, file delivery | none | deep (contacts target) |
| **External sources** | | | |
| RDAP (IANA bootstrap) | Registrar, registration/expiry dates, status, nameservers, network owner, abuse contacts | none | quick + deep |
| RIPEstat | Origin AS, announced prefix, AS holder, announced space | none | quick + deep |
| Cert Spotter | Certificate issuances and names from CT logs | optional | quick + deep |
| crt.sh | CT history for domains; certificate lookup by fingerprint | none | deep for domains |
| VirusTotal | Engine verdicts, reputation, popular threat labels | **required** | quick + deep |
| AbuseIPDB | Abuse confidence, report categories, Tor exits | **required** | quick + deep |
| GreyNoise Community | Internet scanner / RIOT (known benign service) classification | optional | quick + deep |
| AlienVault OTX | Community pulses, malware families, ATT&CK technique tags, allowlist validation | optional | quick (IP, hashes) + deep |
| ThreatFox · URLhaus · MalwareBazaar (abuse.ch) | IOC listings, malware URLs, known samples | **required** (one abuse.ch Auth-Key) | quick + deep |
| Feodo Tracker (abuse.ch) | Botnet C2 blocklist (public feed) | none | quick + deep |
| YARAify (abuse.ch) | YARA and ClamAV hits for hashes | optional | quick + deep |
| Shodan InternetDB | Open ports, hostnames, tags, banner-matched CVEs | none | quick + deep |
| CIRCL hashlookup | Known-good files (NSRL and other sets) | none | quick + deep |
| CVE Program (cve.org) | Authoritative CVE record, CNA-declared affected versions, CISA ADP enrichment (CVSS, SSVC) | none | quick + deep |
| NVD | CVSS metrics, CWE, CPE configurations, exploit references | optional | quick + deep |
| CISA KEV | Known exploited vulnerabilities catalog | none | quick + deep |
| EPSS (FIRST) | Exploit prediction probability and percentile | none | quick + deep |
| **Derived** | | | |
| Hosting infrastructure | Resolved addresses mapped to origin networks and checked against Feodo Tracker | — | quick + deep |
| Known-exploited exposure | InternetDB banner CVEs × CISA KEV (marked unverified: version inference) | — | quick + deep |
| ATT&CK mapping | Malware families → ATT&CK software → techniques | — | quick + deep |
| Cross-source correlation | Corroboration, contradictions, combined signals, CVSS choice | — | quick + deep |

Sources with required keys stay *Not configured* until the key is set; the Observatory shows exactly which environment variable each one reads. Private and special-purpose addresses are never sent to external sources.

## Architecture

```
src/
  app/                      Next.js 16 App Router: pages and JSON API routes
  proxy.ts                  Per-request CSP nonce; optional private-mode gate
  components/               UI: shell, investigation workspace, graph, observatory …
  lib/
    core/types.ts           Shared types (client-safe)
    observables/            Detection, IP classification, URL analysis, extraction, fanging
    net/                    SSRF policy (connect-time address checks), target + provider HTTP clients
    dns/                    RFC 1035 wire codec, DoH resolvers, email-auth parsers
    web/headers.ts          Security header evaluation
    intel/                  ATT&CK index, CVSS parsing, KEV/Feodo feed caches
    providers/
      external/ native/ derived/   One definition per source
      runtime.ts            Execution: auth, cache, quotas, timeouts, error classification
      registry.ts           Plan building and policy skips
    engine/                 Plan runner, investigation lifecycle, summaries
    db/                     Prisma data access (investigations, cache, rate limits, health, IOCs)
    server/                 API helpers: CSRF checks, rate limiting, operator session, logging
scripts/
  investigate.ts            CLI runner (no database needed)
  build-attack-data.mjs     Rebuilds src/data/attack/enterprise.json from MITRE's STIX bundle
```

An investigation is created as `RUNNING` with its plan; the work continues after the HTTP response (`after()`), each source's outcome is written as soon as it finishes, and the workspace polls until the record is final. If a worker dies (deployment, timeout), the investigation is closed on next read with the unfinished steps recorded as timed out.

Provider responses are validated with Zod schemas before use. Successful and empty answers are cached per source TTL in Postgres; local request budgets (e.g. VirusTotal 4/min, 500/day) are enforced with atomic counters shared by every server instance.

## Security model

- **SSRF** — requests to user-supplied targets (TLS, HTTP, MTA-STS) allow only `http`/`https` on ports 80, 443, 8080 and 8443. Hostnames such as `localhost`, `*.internal`, `*.local`, `metadata.*` and single-label names are refused. Address checks happen **at connect time** in a custom DNS lookup, so DNS rebinding cannot swap in a private address after validation. Private, loopback, link-local (including 169.254.169.254), CGNAT, multicast, reserved, IPv4-mapped, NAT64 and 6to4 forms are refused. Every redirect is re-validated individually; bodies are capped (512 KB) and every hop has a timeout. Embedded credentials in URLs are stripped.
- **Provider requests** — HTTPS only, redirects limited and re-validated, response size bounded, schema-validated, raw payloads stored with credential-like fields redacted and a 300 KB cap.
- **Browser** — nonce-based CSP with `strict-dynamic` and no third-party origins, `frame-ancestors 'none'`, HSTS, `nosniff`, COOP/CORP, restrictive Permissions-Policy, no `X-Powered-By`.
- **CSRF** — state-changing requests must be same-origin (`Sec-Fetch-Site`/`Origin`) and JSON-encoded.
- **Operator session** — deep investigations, deletions, IOC edits and cache purges require an operator session: the `NOPS_ADMIN_TOKEN` is exchanged (constant-time comparison, rate-limited) for an HMAC-signed, HttpOnly, `SameSite=Strict` cookie valid for 12 hours. Without a token these actions are disabled in production. `NOPS_PRIVATE=1` requires the session for everything.
- **Rate limits** — per-client (hashed address) and instance-wide limits on investigations, connection tests, lookups and unlock attempts.
- **Secrets** — keys are read server-side only; the UI shows which variable is set, never its value. Logs redact credential-like values and connection strings.

## Setup

Requirements: Node.js 20+ and PostgreSQL 14+.

```bash
npm install
cp .env.example .env.local        # set DATABASE_URL (and DIRECT_URL for migrations)
npx prisma migrate deploy
npm run dev
```

### Environment variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | **Required.** Postgres connection used at runtime (use a pooled URL on serverless). |
| `DIRECT_URL` | Direct connection for `prisma migrate deploy`. Not needed at runtime. |
| `NOPS_ADMIN_TOKEN` | Operator token. Without it, operator actions are disabled in production. |
| `NOPS_SESSION_SECRET` | Optional dedicated HMAC key for session cookies. |
| `NOPS_PRIVATE` | `1` to require an operator session everywhere. |
| `VIRUSTOTAL_API_KEY` | VirusTotal (required for that source). |
| `ABUSEIPDB_API_KEY` | AbuseIPDB (required for that source). |
| `ABUSECH_AUTH_KEY` | abuse.ch Auth-Key for ThreatFox, URLhaus, MalwareBazaar (per-product aliases `THREATFOX_API_KEY`, `URLHAUS_API_KEY`, `MALWAREBAZAAR_API_KEY`, `YARAIFY_API_KEY` are also read). |
| `OTX_API_KEY`, `NVD_API_KEY`, `GREYNOISE_API_KEY`, `CERTSPOTTER_API_KEY` | Optional; raise limits or unlock more data. |

### Command line

The engine runs without a database, which is useful for scripting or for checking provider behaviour from another network:

```bash
npm run investigate -- 8.8.8.8
npm run investigate -- example.com --deep --json > result.json
```

## Testing

```bash
npm run lint
npx tsc --noEmit
npm test                      # unit + provider-scenario tests (Vitest)
npm run build && npm run test:e2e   # Playwright against `next start`
```

The unit suite covers detection, IP classification, URL analysis, extraction, the DNS wire codec (against a real captured DNSSEC response), email-auth parsers, header evaluation, CVSS, SSRF policy (including connect-time refusal of loopback, metadata and mapped addresses), sessions, exports (CSV formula neutralisation, defanged reports), the plan runner, planning rules, correlation, and provider-runtime outcomes for success, empty, 401, 403, 404, 429, 5xx, timeouts, network failures, malformed JSON, schema mismatches, partial results, caching and quotas.

The end-to-end suite runs flows that are deterministic offline (private-address and URL-structure investigations), the command bar and palette, finding → evidence → source → raw disclosure, the observatory, operator unlock and IOC extraction, preferences, security headers and CSRF rejection, and a mobile flow. Set `E2E_OPERATOR_TOKEN` to the server's `NOPS_ADMIN_TOKEN` to include the operator test.

## Deployment

Deployed on Vercel (region `lhr1`, next to the Supabase database in eu-west-2). Build command is the default `next build`; migrations are applied explicitly with `npx prisma migrate deploy` using `DIRECT_URL`, not during the build. Set `DATABASE_URL`, `NOPS_ADMIN_TOKEN`, `NOPS_SESSION_SECRET` and any provider keys in the project's environment variables.

## Limitations

- Sources that require keys return nothing until keys are configured; findings reflect only the sources that answered, and the workspace says which ones failed.
- Absence from threat-intelligence feeds is not evidence of safety — the correlation finding says so explicitly.
- InternetDB's CVE associations are inferred from banner versions and can be wrong for backported software; they are labelled unverified.
- DKIM detection probes common selectors only; selectors are arbitrary, so "none found" does not mean DKIM is unused.
- crt.sh is a shared community service and is frequently slow or unavailable; Cert Spotter covers the same ground more reliably.
- Deep investigations run within a serverless time budget (about 100 s); slow sources past that point are recorded as timeouts.
- Graph layout is limited to the 120 entities nearest the observable.

## Attribution and terms

- MITRE ATT&CK® is a registered trademark of The MITRE Corporation. ATT&CK content © The MITRE Corporation, reproduced under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
- abuse.ch data (Feodo Tracker, ThreatFox, URLhaus, MalwareBazaar, YARAify) is provided under abuse.ch's terms; feeds are CC0.
- Shodan InternetDB is free for non-commercial use. VirusTotal's public API is for non-commercial use.
- RIPEstat requests identify this application via `sourceapp` as RIPE NCC requests.
- EPSS data © FIRST. CISA KEV is a U.S. government work. NVD data courtesy of NIST.
- Archivo and IBM Plex Mono are licensed under the SIL Open Font License. React Flow is MIT-licensed.
