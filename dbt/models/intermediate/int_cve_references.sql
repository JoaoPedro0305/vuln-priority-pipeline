-- What the references of each CVE say: is there public exploit code, a patch,
-- a vendor advisory?
select
    cve_id,
    count(*) as reference_count,
    bool_or(list_contains(tags, 'Exploit')) as has_exploit_reference,
    bool_or(list_contains(tags, 'Patch')) as has_patch_reference,
    bool_or(list_contains(tags, 'Vendor Advisory')) as has_vendor_advisory
from {{ ref('stg_nvd__references') }}
group by cve_id
