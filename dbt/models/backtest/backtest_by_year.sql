-- Coverage per year of decision at a budget of 1,000 CVEs a month: does the
-- ranking hold up over time, and across EPSS model versions?
select
    year(decision_date) as year,
    strategy,
    count(*) as exploited,
    count(*) filter (where rank <= 1000) as caught,
    round(count(*) filter (where rank <= 1000) / count(*), 4) as coverage
from {{ ref('bt_ranks') }}
group by all
order by year, coverage desc
