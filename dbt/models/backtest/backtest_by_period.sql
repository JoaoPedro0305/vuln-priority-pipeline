-- Coverage per strategy and budget, before and after var backtest_split. A
-- ranking that only wins on average, thanks to one period, would show here.
with budgets as (
    select unnest({{ var('backtest_budgets') }}) as budget
),

ranks as (
    select
        *,
        case
            when decision_date < cast('{{ var("backtest_split") }}' as date)
                then 'before {{ var("backtest_split")[:4] }}'
            else 'from {{ var("backtest_split")[:4] }}'
        end as period
    from {{ ref('bt_ranks') }}
)

select
    ranks.period,
    ranks.strategy,
    budgets.budget,
    count(*) as exploited,
    count(*) filter (where ranks.rank <= budgets.budget) as caught,
    round(count(*) filter (where ranks.rank <= budgets.budget) / count(*), 4) as coverage
from ranks
cross join budgets
group by all
order by period, budget, coverage desc
