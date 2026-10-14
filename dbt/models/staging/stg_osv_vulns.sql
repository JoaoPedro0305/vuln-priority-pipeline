-- OSV advisories grouped per flaw (vuln_key): a CVE is often published as a
-- GitHub advisory (GHSA) and as a PyPI one (PYSEC) too.
select
    vuln_key,
    list_sort(list(distinct osv_id)) as osv_ids,
    -- GitHub advisories have the most readable summaries.
    first(summary order by starts_with(osv_id, 'GHSA-') desc, osv_id) filter (where summary is not null) as summary,
    first(cvss3_vector order by osv_id) filter (where cvss3_vector is not null) as cvss3_vector,
    first(cvss4_vector order by osv_id) filter (where cvss4_vector is not null) as cvss4_vector
from {{ source('raw', 'osv_vulns') }}
group by vuln_key
