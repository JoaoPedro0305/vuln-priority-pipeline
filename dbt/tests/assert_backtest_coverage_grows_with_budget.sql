-- A bigger budget can never catch fewer exploited CVEs. A decrease would mean
-- the ranks or the counting are wrong.
select strategy, budget, coverage, previous_coverage
from (
    select
        strategy,
        budget,
        coverage,
        lag(coverage) over (partition by strategy order by budget) as previous_coverage
    from {{ ref('backtest_coverage') }}
)
where coverage < previous_coverage
