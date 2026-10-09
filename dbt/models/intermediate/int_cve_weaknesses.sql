-- The distinct CWE ids of each CVE, from any source, without NVD's
-- placeholders (NVD-CWE-noinfo, NVD-CWE-Other).
select
    cve_id,
    list_sort(list(distinct cwe_id)) as cwe_ids
from {{ ref('stg_nvd__weaknesses') }}
where is_specific
group by cve_id
