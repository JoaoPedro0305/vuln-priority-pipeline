# vuln-priority-pipeline

[![ci](https://github.com/JoaoPedro0305/vuln-priority-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/JoaoPedro0305/vuln-priority-pipeline/actions/workflows/ci.yml)
[![codeql](https://github.com/JoaoPedro0305/vuln-priority-pipeline/actions/workflows/codeql.yml/badge.svg)](https://github.com/JoaoPedro0305/vuln-priority-pipeline/actions/workflows/codeql.yml)
[![live sources](https://github.com/JoaoPedro0305/vuln-priority-pipeline/actions/workflows/live-sources.yml/badge.svg)](https://github.com/JoaoPedro0305/vuln-priority-pipeline/actions/workflows/live-sources.yml)

Daily pipeline that ranks CVEs by real-world exploitation risk (NVD + CISA KEV + EPSS),
backtests patching strategies and publishes a live dashboard.

## The question

Tens of thousands of CVEs are published every year and most teams can patch only a fraction of them.
Sorting by CVSS severity is the usual answer, but severity measures how bad an exploit *would* be,
not how likely one is. This project asks a measurable question:

> With a fixed patching budget, which prioritization rule catches the most vulnerabilities
> that end up exploited in the wild?

**Answer, from 57 monthly decisions (2022-2026)**: patching the 1,000 highest-CVSS CVEs a month
would have caught **1.1%** of the CVEs exploited the following month, barely better than chance.
EPSS alone catches **16.3%**, and this project's ranking (CISA's exploitation evidence, then EPSS)
**21.9%**, in every year of the period. [Details below](#backtest-does-the-ranking-work).

It combines three public sources:

| Source | What it says | Role here |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs with evidence of exploitation, and the date each was added | Ground truth: "was exploited" |
| [EPSS](https://www.first.org/epss/) (FIRST) | Daily probability of exploitation in the next 30 days, for every CVE | Predictive signal, with daily history since 2021 |
| [NVD](https://nvd.nist.gov/) | CVSS severity, affected products (CPE), weakness type (CWE) | Severity and context |

## Status

Built in stages, one pull request each:

- [x] **1. Ingestion of KEV and EPSS** into a DuckDB raw layer, validated before every load
- [x] **2. NVD ingestion**: full rebuild from the yearly feeds, daily increments from the API
- [x] **3. dbt models**: staging, intermediate and a `cves` mart, with data tests, a unit test and a contract
- [x] **4. Priority ranking** from CISA's SSVC decision table and the BOD 26-04 remediation timelines
- [x] **5. Backtest** of patching strategies on 57 months of point-in-time EPSS and KEV
- [x] **6. Dependencies of real systems**: resolved with pip, matched through OSV.dev, decided per system
- [ ] 7. Daily run and public dashboard on GitHub Pages
- [ ] 8. Automatic issue when a dependency enters KEV
- [ ] 9. OpenSSF Scorecard and v1.0 release

## How it works (so far)

```mermaid
flowchart TD
    KEV["CISA KEV<br/>JSON, whole catalog"] --> DL
    EPSS["FIRST EPSS<br/>gzipped CSV, one per day"] --> DL
    FEEDS["NVD yearly feeds<br/>gzipped JSON + .meta hash"] --> DL
    API["NVD CVE API<br/>changes since last sync"] --> DL
    DL["download.py<br/>retries, size limit, SHA-256,<br/>atomic write"] --> LAND[("data/landing/<br/>files as served")]
    LAND --> VAL["sources/kev.py, epss.py, nvd.py<br/>parse and validate"]
    VAL -->|"all checks pass:<br/>one transaction"| RAW[("DuckDB raw layer<br/>raw.kev, raw.epss, raw.nvd,<br/>raw.nvd_sync, raw.load_log")]
    VAL -->|"any check fails"| KEEP["load refused,<br/>warehouse unchanged"]
```

- **ELT.** Files are saved exactly as served, then loaded into a raw layer that only types the
  columns. Cleaning and joining will happen in SQL (dbt), where every step can be tested and read.
- **Validate before loading.** KEV: header count matches the entries, CVE ids are well formed and
  unique, dates parse, and a catalog much smaller than the one loaded is refused. EPSS: no
  duplicates, scores and percentiles within [0, 1], a minimum row count. NVD: valid ids, dates and
  status on every CVE. A failed check leaves the warehouse as it was.
- **Three EPSS formats.** The daily file gained a `percentile` column in 2021 and a header line
  with the model version in February 2022; all three formats load, and each row keeps the model
  version that scored it.
- **Provenance.** `raw.load_log` records every load: source version, row count, final URL and the
  SHA-256 of the file.
- **Stalled transfers.** A connection that slows to a trickle never hits the read timeout, so
  each download is also held to a minimum speed (50 KB/s over 30 s windows) and started again
  up to 3 times. NVD feeds do this: one stalled at 15 KB/s, then took seconds on a new connection.

### NVD: full and incremental

`vulnprio ingest nvd` decides on its own:

| Situation | What it does |
|---|---|
| First run, `--full`, or last sync over 90 days ago | Downloads the 25 yearly feeds (2002 to now, ~225 MB compressed), checks each against the SHA-256 in its `.meta` file and loads them one at a time. Feeds unchanged since their last load are skipped before downloading. |
| Last sync within 90 days | Asks the CVE API for everything modified since then, minus one day of overlap: a few requests instead of 225 MB. |

- **Watermark.** `raw.nvd_sync` records how far each complete sync covers: the end of the API
  window, or after a feed rebuild the latest `lastModified` loaded. (Not the age of the oldest
  feed: NVD only regenerates a yearly feed when one of its CVEs changes, so the 2003 file can be
  weeks old and still current.) The next incremental run starts there, minus one day.
- **Why the overlap.** NVD sometimes makes a change visible in the API minutes after its
  `lastModified` time. In testing, a run caught 35 CVEs inside a window that a run 3 minutes
  earlier had already covered.
- **Order-independent merge.** A stored CVE is only replaced by a version with an equal or later
  `lastModified`, so an older feed loaded after a newer API page changes nothing, and any load can
  be repeated safely. A CVE that changes while the API is being paged through arrives twice; the
  latest copy wins.
- **Rate limit.** Without a key the API allows 5 requests per 30 s, so requests are spaced 6 s
  apart; with the free `NVD_API_KEY` (sent as a header, never in the URL) 0.6 s. 403, 429 and 5xx
  answers are retried with backoff.
- **What is kept.** Scalar fields are typed; `metrics` (CVSS v2, v3.0, v3.1 and v4.0, from NVD and
  from the CNA), `weaknesses` and `references` stay as published JSON for dbt to interpret. The
  configurations tree, the largest field, is reduced to the distinct vulnerable CPE strings.
- **Checked against the source.** After a full rebuild and two incremental runs the table held
  403,636 CVEs, exactly the `totalResults` the API reported at that moment. A full rebuild takes
  about 5 to 15 minutes depending on NVD's servers; a daily incremental run about 30 seconds.
- **Why not the "modified" feed?** NVD documents a feed with the last 8 days of changes, but it
  answered 404 throughout development (its `.meta` file exists). The API covers the same need.

## Transformation (dbt)

`vulnprio transform` runs `dbt build`: every model and its tests, in dependency order, so a model
whose tests fail stops everything built on it. The full run takes about a minute.

```mermaid
flowchart LR
    subgraph raw
        R1[raw.kev]
        R2[raw.epss]
        R3[raw.nvd]
    end
    subgraph staging["staging (views)"]
        S1[stg_kev]
        S2[stg_epss]
        S3[stg_nvd__cves]
        S4[stg_nvd__cvss]
        S5[stg_nvd__ssvc]
        S6[stg_nvd__weaknesses]
        S7[stg_nvd__references]
    end
    subgraph intermediate
        I1[int_cve_cvss]
        I2[int_cve_ssvc]
        I3[int_cve_weaknesses]
        I4[int_cve_products]
        I5[int_cve_references]
        I6[int_epss_latest]
    end
    R1 --> S1
    R2 --> S2
    R3 --> S3 & S4 & S5 & S6 & S7
    S4 --> I1
    S3 --> I1 & I4
    S5 --> I2
    S6 --> I3
    S7 --> I5
    S2 --> I6
    S1 & I1 & I2 & I3 & I4 & I5 & I6 --> M[(marts.cves)]
```

- **staging** unpacks NVD's nested JSON into one row per entry (CVSS score, SSVC assessment,
  weakness, reference) and trims and types everything else.
- **intermediate** holds the decisions, one per model. The main one, `int_cve_cvss`, picks one
  CVSS score per CVE: NVD first (an independent analyst), then the CNA that published the CVE,
  then anyone else; newer version on ties; and v3 as the headline score, the version most CVEs
  have and the one patching thresholds (7.0, 9.0) were defined on.
- **marts.cves** has one row per published CVE (385,178; 18,458 rejected ids left out): severity,
  CWE, products, KEV status, exploit references, CISA's SSVC assessment and the latest EPSS score.
  Its **contract** fails the build if a column disappears or changes type.
- **Tests**: 45 data tests (keys unique and present, accepted values, scores within range, every
  KEV CVE reaching the mart, CVSS v3 severity matching its score), source freshness thresholds,
  and **unit tests** of the CVSS choice and of the priority rules on hand-made rows. A pytest run builds the whole project
  on a small warehouse, so CI checks the SQL on every pull request.

### What the data already shows

**Severity depends on who you ask.** Of 58,491 CVEs scored with CVSS 3.1 by both NVD and the CNA,
75% got different scores, 58% differ by a full point or more, and 30% land on opposite sides of
the 7.0 "high" line.

**NVD now scores a minority of new CVEs.** Share of each year's CVEs whose v3 score comes from NVD:

| Published | CVEs | Scored by NVD | Only by the CNA | Only by others (e.g. CISA) | No v3 score |
|---|---:|---:|---:|---:|---:|
| 2022 | 25,073 | 92% | 8% | 0% | 0% |
| 2023 | 28,816 | 92% | 8% | 0% | 0% |
| 2024 | 39,953 | 58% | 28% | 14% | 1% |
| 2025 | 48,152 | 37% | 47% | 16% | 6% |
| 2026 (to Oct.) | 76,299 | 20% | 64% | 16% | 10% |

That is why the score keeps a `cvss3_provider` column, and why severity alone is a shaky basis for
prioritization.

## Priority ranking

`marts.cve_priorities` ranks every published CVE with CISA's own decision tables, copied as dbt
seeds from the SSVC project of CERT/CC (pinned to a commit):

| Table | Inputs | Output |
|---|---|---|
| SSVC, CISA Coordinator 2.0.3 | exploitation, automatable, technical impact, mission impact | track, track\*, attend, act |
| BOD 26-04 timelines | in KEV, publicly exposed, automatable, technical impact | fix in 3 days (+ forensic check), 3, 14 or 60 days, or on upgrade |

`priority_rank` puts known exploitation (KEV) first, then SSVC *act* and *attend*, then EPSS,
then CVSS; the BOD 26-04 timeline is each CVE's deadline. That order is the one the
[backtest](#backtest-does-the-ranking-work) supports. `priority_reason` says why in words:

```text
$ vulnprio top --limit 3
   rank  cve             product                           fix within        ssvc    why
      1  CVE-2024-3400   Palo Alto Networks PAN-OS         3 days+forensics  act     exploited in the wild (KEV, ransomware); automatable; total control; EPSS 99.9%; CVSS 10.0
      2  CVE-2021-44228  Apache Log4j2                     3 days+forensics  act     exploited in the wild (KEV, ransomware); automatable; total control; EPSS 99.9%; CVSS 10.0
      3  CVE-2019-11510  Ivanti Pulse Connect Secure       3 days+forensics  act     exploited in the wild (KEV, ransomware); automatable; total control; EPSS 99.9%; CVSS 10.0
```

**Where the inputs come from.** CISA assessed about half of all CVEs (197k). For the rest the
inputs are derived, and the derivation was checked against CISA's answers on the 190k CVEs that
have both:

| Input | Derived from | Agrees with CISA |
|---|---|---:|
| Automatable | CVSS vector: network, low complexity, no privileges, no user interaction | 92% |
| Technical impact | CVSS vector: high confidentiality and integrity impact ("total control") | 90% |
| Exploitation | in KEV = active; NVD reference tagged "Exploit" = proof of concept | 88% |

Exploitation takes the **strongest** evidence available: CISA's assessment can predate the CVE's
addition to KEV. CVEs with no vector at all (3,357) default to "not automatable, partial impact"
and say so in `automatable_source = 'unknown'`.

**Organisation inputs.** Mission impact and internet exposure describe your systems, not the
vulnerability, so they are dbt variables (defaults: medium, exposed):

```bash
vulnprio transform --mission-impact high --publicly-exposed no
```

**What it shows.** At medium mission impact, SSVC says *act* or *attend* almost only for
vulnerabilities already exploited (1,600 of 1,605 are in KEV): it waits for evidence. The other
~384,000 CVEs are *track* or *track\**, and within those the order comes from EPSS.

## Backtest: does the ranking work?

Each month from January 2022 to September 2026 (57 decisions), the backtest asks every strategy
to rank all open CVEs **with only what was known that day**, then checks which CVEs entered CISA
KEV in the following 30 days.

![Coverage by monthly budget](docs/img/backtest_coverage.png)

| Strategy | 100 a month (0.04% of open CVEs) | 500 (0.21%) | 1,000 (0.42%) | 5,000 (2.10%) | 10,000 (4.19%) |
|---|---:|---:|---:|---:|---:|
| **This project: SSVC act/attend, then EPSS** | **10.6%** | **17.3%** | **21.9%** | **34.8%** | **41.9%** |
| EPSS alone | 5.1% | 11.7% | 16.3% | 30.0% | 37.8% |
| Act, attend, track\*, then EPSS (dropped) | 9.8% | 15.2% | 19.1% | 30.1% | 37.7% |
| BOD 26-04 timeline first (dropped) | 7.5% | 11.4% | 13.8% | 20.4% | 23.5% |
| CVSS alone | 0.2% | 0.4% | 1.1% | 3.1% | 11.2% |
| Random | 0.1% | 0.1% | 0.2% | 2.8% | 5.5% |

*Share of the CVEs exploited in the next 30 days that each strategy had ranked within the monthly
budget. 932 such CVEs; about 238,600 open CVEs per month.*

**What it says:**

- **CVSS barely beats chance.** Patching the 1,000 highest-CVSS CVEs a month caught 1.1% of what
  was exploited next; in 2023 and 2024, none. Thousands of CVEs share a 9.8, and severity says how
  bad an exploit would be, not how likely one is.
- **EPSS is 15 times better than CVSS** at the same effort, and evidence of exploitation that CISA
  recorded before a CVE reached KEV (SSVC *act*/*attend*) adds to it: 21.9% at 1,000 a month.
- **A third of exploitation cannot be caught monthly.** Besides the 932 CVEs above, 453 KEV
  additions in those windows (32%) were CVEs published *after* the decision date. A monthly
  cycle never sees them; only faster cycles or compensating controls do.

**How the ranking got here.** The first version ordered by the BOD 26-04 timeline: impact before
likelihood. It put ~36,000 "automatable, total impact" CVEs ahead of likely ones and lost to EPSS
alone. The second ordered SSVC *track\** before *track*; from 2025, when CISA recorded thousands
of public proofs of concept, those *track\** CVEs (none of which entered KEV within a month)
pushed likely ones down. The final order treats *track* and *track\** alike, as SSVC itself does
(both mean "standard timelines"). All three are kept in the backtest. Because the last change was
made after looking at 2025-2026, the result is shown per period as well, and it holds in both:

| Strategy, 1,000 CVEs a month | Before 2025 (670 exploited) | From 2025 (262 exploited) |
|---|---:|---:|
| **This project: SSVC act/attend, then EPSS** | **21.3%** | **23.3%** |
| EPSS alone | 19.6% | 8.0% |
| Act, attend, track\*, then EPSS (dropped) | 20.4% | 15.7% |
| BOD 26-04 timeline first (dropped) | 13.7% | 14.1% |
| CVSS alone | 1.0% | 1.1% |

![Coverage per year](docs/img/backtest_by_year.png)

**Point in time.** On each decision date a CVE is a candidate only if it was published, not yet in
KEV and scored by EPSS that day; it gets that day's EPSS score, and CISA's SSVC assessment only if
it was made before that day. A dbt unit test breaks if any of these rules is removed. Ties are
broken by `md5(cve_id)`, which carries no information.

**Limitations.**

- KEV is a lower bound of exploitation: it lists what CISA confirmed, with a US-government focus.
- CVSS scores and vectors are today's, not the date's; NVD's "Exploit" reference tags are not used
  in the backtest at all, because they carry no date.
- Only the latest CISA assessment of each CVE is available; one made after the date is ignored,
  so earlier, different assessments are lost rather than leaked.
- EPSS predicts exploitation activity, not KEV listing, which can lag it.

Reproduce with `vulnprio ingest epss --monthly-since 2021-12-01`, `vulnprio transform` and
`vulnprio report` (which prints these tables and draws the charts).

## Your own dependencies

The same ranking, applied to real systems. `assets.toml` lists them: a GitHub repository or a
local folder, its requirement files, and the two facts CISA's tables need about the system itself,
whether it is reachable from the internet and how much depends on it.

```bash
vulnprio ingest deps      # resolve, match against OSV.dev
vulnprio transform        # decide per asset
vulnprio findings         # what to upgrade, most urgent first
```

```text
asset                             exposed  impact   packages vulnerable  flaws  fix within
example: legacy web app           yes      high           15          7     84  3 days
brazil-economic-data-pipeline     no       low            22          0      0  -
ssh-bruteforce-analysis           no       low            35          0      0  -
vuln-priority-pipeline            no       low            93          0      0  -

Upgrades, most urgent first:
  example: legacy web app: django 2.2 -> 5.2.17
      fixes 43 vulnerabilities; attend, within 3 days; worst: CVE-2020-7471
  example: legacy web app: requests 2.19.0 -> 2.33.0
      fixes 5 vulnerabilities; attend, within 14 days; worst: CVE-2018-18074
  ...
```

The three real repositories (150 packages counting transitive ones, all pinned and kept current
by Dependabot) have no known vulnerability. The "legacy web app" is an
[intentional example](examples/legacy-web-app/README.md) with 2017-2019 versions, there to show
what findings look like.

**How it works.**

1. **Requirement files are untrusted input.** Only package requirements and `-r`/`-c` includes
   inside the same tree are accepted. Anything that could point pip elsewhere (`--index-url`,
   `--find-links`, `-e`, direct URLs, `../` paths) is refused with the file and line.
2. **Transitive dependencies count.** pip resolves the full set with `install --dry-run --report`,
   for Linux and the asset's Python version, **wheels only**: nothing is installed and no package
   code runs. Packages published only as source need their build script run to reveal their own
   dependencies; that is allowed only for assets marked `trust_build_scripts` (this repository,
   because of `dbt-core-experimental-parser`). One pip limitation remains: environment markers
   such as `colorama; sys_platform == "win32"` are evaluated for the machine running the scan, so
   a scan on Windows lists a few Windows-only packages (22 instead of 19 for one repository). The
   scheduled scan runs on Linux.
3. **[OSV.dev](https://osv.dev)** says which advisories affect each version. The same flaw often
   appears as a GitHub advisory, a PyPI advisory and a CVE; they are grouped under the CVE id, and
   OSV records are cached by their modification time.
4. **Fix versions** come from the advisories' affected ranges, compared with Python's version
   rules (`2.10` > `2.9`). For each package, the upgrade target is the version that fixes every
   known flaw.
5. **A decision per asset.** CVE facts (KEV, EPSS, exploitation, automatable, impact) come from
   `cve_priorities`; the asset supplies exposure and mission impact. The same CVE can be *act*
   within 3 days on an internet-facing system and *attend* within 14 days on an internal job (a
   dbt unit test checks exactly that). Flaws without a CVE are judged from their OSV CVSS vector.

**Why not just Dependabot alerts?** They cover one repository at a time and sort by CVSS severity,
which the backtest shows barely predicts exploitation. This adds one view across systems, ranked by
exploitation evidence and EPSS, with a deadline that depends on each system's exposure.

## Run it

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt -e .

vulnprio ingest all              # KEV catalog, latest EPSS day, NVD (full first, then incremental)
vulnprio ingest epss --date 2023-03-07
vulnprio ingest epss --monthly-since 2021-12-01   # EPSS history for the backtest (~80 s)
vulnprio ingest nvd --years 2024 # only some yearly feeds
vulnprio ingest nvd --since 2026-10-01
vulnprio transform               # dbt build: models + tests
vulnprio transform --select marts
vulnprio top --vendor apache --since 2025-01-01
vulnprio report                  # backtest tables and charts (docs/img)
vulnprio ingest deps             # dependencies of the systems in assets.toml
vulnprio findings --details      # their vulnerabilities and upgrades (after transform)
vulnprio status
```

```text
source  version             rows  loaded at
epss    2026-10-09       384,993  2026-10-09 16:24 UTC
kev     2026.10.08         1,739  2026-10-09 16:24 UTC
```

Data goes to `data/` (ignored by git); `VULNPRIO_DATA_DIR` and `VULNPRIO_WAREHOUSE` move it.

## Quality and security of the repository itself

- `ci`: ruff (lint, including bandit security rules), 119 tests on Python 3.11 to 3.13 (several build the dbt project), and
  `pip-audit` failing the build on any known vulnerability in the pinned dependencies.
- `codeql`: static analysis of the Python code and of the workflow files.
- `live sources`: weekly run against the real CISA, FIRST, NVD, GitHub and OSV.dev endpoints, so a format change
  is caught even when the code does not change.
- Exact dependency pins and GitHub Actions pinned by commit hash, both updated by Dependabot.
  Workflows run with a read-only token.

## License

MIT. KEV is published by CISA; EPSS scores are published by FIRST. This product uses data from
the NVD API but is not endorsed or certified by the NVD.
