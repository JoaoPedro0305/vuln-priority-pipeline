-- Every loaded EPSS day. epss: probability of exploitation in the next 30 days;
-- percentile: share of all scored CVEs with a lower or equal score that day.
select
    score_date,
    cve_id,
    epss,
    percentile as epss_percentile,
    model_version as epss_model_version
from {{ source('raw', 'epss') }}
