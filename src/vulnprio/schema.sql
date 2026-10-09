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

-- One row per load: what came in, from where, and the file's fingerprint.
CREATE TABLE IF NOT EXISTS raw.load_log (
    source    VARCHAR   NOT NULL,
    version   VARCHAR   NOT NULL,  -- KEV catalog version, EPSS score date, NVD feed year or API window
    row_count BIGINT    NOT NULL,
    url       VARCHAR   NOT NULL,
    sha256    VARCHAR   NOT NULL,
    loaded_at TIMESTAMP NOT NULL
);
