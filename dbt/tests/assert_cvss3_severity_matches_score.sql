-- CVSS v3 severity is defined by the score: 0 none, 0.1-3.9 low, 4.0-6.9
-- medium, 7.0-8.9 high, 9.0-10 critical. A mismatch means a parsing error
-- (or a source publishing inconsistent data).
select cve_id, cvss3_score, cvss3_severity
from {{ ref('cves') }}
where cvss3_score is not null
    and cvss3_severity <> case
        when cvss3_score = 0 then 'NONE'
        when cvss3_score < 4 then 'LOW'
        when cvss3_score < 7 then 'MEDIUM'
        when cvss3_score < 9 then 'HIGH'
        else 'CRITICAL'
    end
