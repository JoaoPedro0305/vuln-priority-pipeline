-- Every CVE known to be exploited must reach the mart: losing one in a join
-- or filter would silently remove the most important rows.
select kev.cve_id
from {{ ref('stg_kev') }} as kev
anti join {{ ref('cves') }} as cves using (cve_id)
