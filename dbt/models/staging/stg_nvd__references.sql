-- One row per reference URL of a CVE, with NVD's tags ("Exploit", "Patch",
-- "Vendor Advisory", ...). An "Exploit" tag means public exploit code or a
-- detailed write-up is linked.
with refs as (
    select
        nvd.cve_id,
        unnest(cast(nvd.refs as json[])) as ref
    from {{ source('raw', 'nvd') }} as nvd
)

select
    cve_id,
    ref ->> 'url' as url,
    ref ->> 'source' as source,
    coalesce(cast(ref -> 'tags' as varchar[]), []) as tags
from refs
