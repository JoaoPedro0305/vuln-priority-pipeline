-- Raw layer: data as the sources publish it, only typed (text -> DATE, DOUBLE).
-- Cleaning, renaming and joining happen later, in the dbt models.
-- Timestamps are UTC.
CREATE SCHEMA IF NOT EXISTS raw;

-- CISA KEV catalog. The feed is always the whole catalog, so each load
-- replaces the table; date_added keeps when each CVE entered the catalog.
CREATE TABLE IF NOT EXISTS raw.kev (
    cve_id               VARCHAR PRIMARY KEY,
    vendor_project       VARCHAR NOT NULL,
    product              VARCHAR NOT NULL,
    vulnerability_name   VARCHAR NOT NULL,
    date_added           DATE    NOT NULL,
    short_description    VARCHAR,
    required_action      VARCHAR,
    due_date             DATE,
    known_ransomware_use VARCHAR,
    notes                VARCHAR,
    cwes                 VARCHAR[],
    catalog_version      VARCHAR NOT NULL,
    loaded_at            TIMESTAMP NOT NULL
);

-- EPSS: one row per CVE per scored day. Reloading a day replaces that day.
-- No primary key: over hundreds of millions of rows the index would cost more
-- than it protects. The load checks uniqueness before it commits instead.
CREATE TABLE IF NOT EXISTS raw.epss (
    score_date    DATE    NOT NULL,
    cve_id        VARCHAR NOT NULL,
    epss          DOUBLE  NOT NULL,
    percentile    DOUBLE,   -- absent from the first files (2021)
    model_version VARCHAR,  -- stated in the file only from February 2022 on
    loaded_at     TIMESTAMP NOT NULL
);

-- NVD: one row per CVE, always its most recent version. Nested fields
-- (metrics, weaknesses, references) stay as published JSON; dbt picks the
-- CVSS score from them. The configurations tree (affected products, the
-- largest field) is reduced to its distinct vulnerable CPE strings.
CREATE TABLE IF NOT EXISTS raw.nvd (
    cve_id            VARCHAR   NOT NULL,
    source_identifier VARCHAR,
    published         TIMESTAMP NOT NULL,
    last_modified     TIMESTAMP NOT NULL,
    vuln_status       VARCHAR   NOT NULL,  -- Analyzed, Modified, Deferred, Rejected...
    cve_tags          JSON,
    description_en    VARCHAR,
    metrics           JSON,                -- CVSS v2 / v3.0 / v3.1 / v4.0, from NVD and the CNA
    weaknesses        JSON,                -- CWE ids
    refs              JSON,                -- reference URLs with tags such as "Exploit" or "Patch"
    cpes              VARCHAR[],
    loaded_at         TIMESTAMP NOT NULL
);

-- Each complete NVD sync and the modification time it covers up to. The next
-- incremental run asks the API for everything modified since then.
CREATE TABLE IF NOT EXISTS raw.nvd_sync (
    mode          VARCHAR   NOT NULL,  -- 'feeds' (full rebuild) or 'api' (incremental)
    covered_until TIMESTAMP NOT NULL,
    cve_count     BIGINT    NOT NULL,  -- CVEs received in this sync
    finished_at   TIMESTAMP NOT NULL
);

-- Dependencies of the systems listed in assets.toml, and the OSV.dev
-- vulnerabilities that affect them. Each asset is replaced on every scan.
CREATE TABLE IF NOT EXISTS raw.assets (
    asset            VARCHAR PRIMARY KEY,
    location         VARCHAR NOT NULL,   -- github:owner/repo@ref or local:path
    requirements     VARCHAR[] NOT NULL,
    python           VARCHAR NOT NULL,
    publicly_exposed VARCHAR NOT NULL,
    mission_impact   VARCHAR NOT NULL,
    loaded_at        TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS raw.asset_packages (
    asset     VARCHAR NOT NULL,
    package   VARCHAR NOT NULL,  -- canonical PyPI name
    version   VARCHAR NOT NULL,
    is_direct BOOLEAN NOT NULL,  -- listed in the requirement files, not pulled in by another package
    upgrade_to VARCHAR,          -- lowest version fixing every known flaw that has a fix; NULL if none
    loaded_at TIMESTAMP NOT NULL
);

-- One row per (asset, package, flaw); advisories describing the same flaw
-- (GHSA, PYSEC, CVE aliases) are grouped under vuln_key.
CREATE TABLE IF NOT EXISTS raw.asset_vulns (
    asset     VARCHAR NOT NULL,
    package   VARCHAR NOT NULL,
    version   VARCHAR NOT NULL,
    vuln_key  VARCHAR NOT NULL,  -- the CVE id, or the smallest advisory id
    osv_ids   VARCHAR[] NOT NULL,
    fixed_in  VARCHAR,           -- first version fixing every advisory; NULL if none yet
    loaded_at TIMESTAMP NOT NULL
);

-- OSV vulnerability records, cached by their "modified" time.
CREATE TABLE IF NOT EXISTS raw.osv_vulns (
    osv_id    VARCHAR PRIMARY KEY,
    vuln_key  VARCHAR NOT NULL,
    aliases   VARCHAR[] NOT NULL,
    summary   VARCHAR,
    cvss3_vector VARCHAR,
    cvss4_vector VARCHAR,
    modified  VARCHAR NOT NULL,
    affected  JSON,
    loaded_at TIMESTAMP NOT NULL
);

-- One row per load: what came in, from where, and the file's fingerprint.
CREATE TABLE IF NOT EXISTS raw.load_log (
    source    VARCHAR   NOT NULL,
    version   VARCHAR   NOT NULL,  -- KEV catalog version, EPSS score date, NVD feed year or API window
    row_count BIGINT    NOT NULL,
    url       VARCHAR   NOT NULL,
    sha256    VARCHAR   NOT NULL,
    loaded_at TIMESTAMP NOT NULL
);
