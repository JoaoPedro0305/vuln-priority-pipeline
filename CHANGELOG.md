# Changelog

## 1.0.0 - 2026-10-14

First release. The pipeline runs every day and publishes its results at
https://joaopedro0305.github.io/vuln-priority-pipeline/.

**Ingestion** (`vulnprio ingest`)
- CISA KEV and FIRST EPSS into a DuckDB raw layer, each file validated before it is loaded, in one
  transaction; all three historical EPSS formats; monthly EPSS history since 2021 for the backtest.
- NVD: full rebuild from the yearly feeds (checked against the SHA-256 in their `.meta` files),
  then incremental updates from the CVE API with a watermark; order-independent merge.
- Downloads with retries, size limits, a minimum speed (stalled transfers are restarted) and
  atomic writes.

**Models** (`vulnprio transform`, dbt)
- Staging, intermediate and marts with 100+ data tests, unit tests and enforced contracts.
- One CVSS score per CVE (NVD, then the CNA, then others), CISA's SSVC assessments, CWEs, products.
- `cve_priorities`: CISA's SSVC decision table and BOD 26-04 timelines, inputs from CISA or derived
  from the CVSS vector (88-92% agreement with CISA), ranked by known exploitation, SSVC act/attend,
  then EPSS.

**Backtest** (57 monthly decisions, 2022-2026, point in time)
- At 1,000 CVEs a month: CVSS catches 1.1% of next-month exploitation, EPSS 16.3%, this ranking
  21.9%, in every year and before and after 2025.

**Real systems** (`vulnprio ingest deps`, `findings`)
- Dependencies of the assets in `assets.toml`, resolved by pip without installing anything, matched
  against OSV.dev, decided per asset, with an upgrade plan.
- A GitHub issue opens when a dependency has an exploited flaw, and closes when it is fixed.

**Publishing**
- Daily GitHub Actions run, static dashboard on GitHub Pages (no external code, strict CSP), dbt
  documentation.

**Supply chain**
- Dependencies pinned by hash (universal uv locks), Actions pinned by commit, least-privilege
  workflow tokens, CodeQL, pip-audit, OpenSSF Scorecard, SECURITY.md with private reporting.
- Release artifacts come with signed SLSA build provenance (`gh attestation verify`).
