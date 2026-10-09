-- One row per CVE with its scalar fields. The nested fields are unpacked by
-- the other stg_nvd__* models, one row per entry.
select
    cve_id,
    source_identifier,
    published,
    last_modified,
    vuln_status,
    vuln_status = 'Rejected' as is_rejected,
    trim(description_en) as description,
    -- [{"sourceIdentifier": ..., "tags": ["disputed"]}] -> ['disputed']
    coalesce(
        list_sort(list_distinct(flatten(
            [cast(t -> 'tags' as varchar[]) for t in cast(cve_tags as json[])]
        ))),
        []
    ) as cve_tags,
    cpes
from {{ source('raw', 'nvd') }}
