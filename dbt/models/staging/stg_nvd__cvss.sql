-- One row per CVSS score attached to a CVE. A CVE can have several: one per
-- CVSS version (2.0, 3.0, 3.1, 4.0) and, within a version, one from NVD
-- ("Primary") plus others from the CNA that published it and from ADPs such as
-- CISA ("Secondary"). int_cve_cvss chooses between them.
with entries as (
    select
        nvd.cve_id,
        unnest(cast(metric.value as json[])) as entry
    from {{ source('raw', 'nvd') }} as nvd,
        json_each(nvd.metrics) as metric
    where metric.key like 'cvssMetricV%'
)

select
    cve_id,
    entry -> 'cvssData' ->> 'version' as cvss_version,
    entry ->> 'source' as source,
    entry ->> 'type' as source_type,
    cast(entry -> 'cvssData' ->> 'baseScore' as decimal(3, 1)) as base_score,
    -- v3 and v4 keep the severity inside cvssData, v2 next to it.
    upper(coalesce(entry -> 'cvssData' ->> 'baseSeverity', entry ->> 'baseSeverity')) as base_severity,
    entry -> 'cvssData' ->> 'vectorString' as vector
from entries
