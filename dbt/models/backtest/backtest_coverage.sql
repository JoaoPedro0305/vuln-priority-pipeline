{#
    The answer to the project's question, per strategy and monthly budget:

    coverage    share of the CVEs exploited in the next window that the strategy
                had ranked within the budget (higher = fewer surprises)
    efficiency  share of the patched CVEs that were then exploited (higher = less
                wasted work)
    budget_share  the budget as a share of all open CVEs, for scale
#}
with budgets as (
    select unnest({{ var('backtest_budgets') }}) as budget
),

cycles as (
    select count(*) as cycles, avg(candidates) as avg_candidates
    from (select decision_date, count(*) as candidates from {{ ref('bt_candidates') }} group by all)
)

select
    ranks.strategy,
    budgets.budget,
    count(*) filter (where ranks.rank <= budgets.budget) as caught,
    count(*) as exploited,
    round(count(*) filter (where ranks.rank <= budgets.budget) / count(*), 4) as coverage,
    round(count(*) filter (where ranks.rank <= budgets.budget) / (budgets.budget * any_value(cycles.cycles)), 6)
        as efficiency,
    round(budgets.budget / any_value(cycles.avg_candidates), 4) as budget_share,
    any_value(cycles.cycles) as cycles
from {{ ref('bt_ranks') }} as ranks
cross join budgets
cross join cycles
group by ranks.strategy, budgets.budget
order by budgets.budget, coverage desc
