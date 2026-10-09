-- Scores of the most recent EPSS day only. A CVE missing from that day (e.g.
-- rejected since) gets no score instead of an outdated one.
select
    cve_id,
    epss,
    epss_percentile,
    epss_model_version,
    score_date as epss_date
from {{ ref('stg_epss') }}
where score_date = (select max(score_date) from {{ ref('stg_epss') }})
