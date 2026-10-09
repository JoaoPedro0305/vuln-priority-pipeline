-- CISA's latest SSVC assessment of each CVE. Other roles (the CNA, a supplier)
-- assessed only a few dozen CVEs, so CISA's is the one used consistently.
select
    cve_id,
    assessed_at as ssvc_assessed_at,
    exploitation as ssvc_exploitation,
    automatable as ssvc_automatable,
    technical_impact as ssvc_technical_impact
from {{ ref('stg_nvd__ssvc') }}
where role = 'CISA Coordinator'
qualify row_number() over (partition by cve_id order by assessed_at desc) = 1
