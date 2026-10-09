-- One row per (CVE, source, weakness). Besides real CWE ids, NVD uses two
-- placeholders: NVD-CWE-noinfo (not enough information) and NVD-CWE-Other.
with weaknesses as (
    select
        nvd.cve_id,
        unnest(cast(nvd.weaknesses as json[])) as weakness
    from {{ source('raw', 'nvd') }} as nvd
),

descriptions as (
    select
        cve_id,
        weakness ->> 'source' as source,
        weakness ->> 'type' as source_type,
        unnest(cast(weakness -> 'description' as json[])) as description
    from weaknesses
)

select distinct
    cve_id,
    source,
    source_type,
    description ->> 'value' as cwe_id,
    starts_with(description ->> 'value', 'CWE-') as is_specific
from descriptions
where description ->> 'lang' = 'en'
