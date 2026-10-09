-- The monthly decision dates of the backtest: the first loaded EPSS day of
-- each month (normally the 1st; the next day when FIRST skipped the 1st), as
-- long as the whole outcome window has already happened.
with months as (
    select min(score_date) as decision_date
    from {{ ref('stg_epss') }}
    group by date_trunc('month', score_date)
)

select
    decision_date,
    decision_date + {{ var('backtest_window_days') }} as window_end
from months
where decision_date >= cast('{{ var("backtest_start") }}' as date)
    and decision_date + {{ var('backtest_window_days') }}
        <= (select max(date_added) from {{ ref('stg_kev') }})
