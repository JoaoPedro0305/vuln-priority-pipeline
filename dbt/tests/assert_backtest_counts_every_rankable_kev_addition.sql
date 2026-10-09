-- Every KEV addition that a monthly cycle could rank must appear, once per
-- strategy, in bt_ranks; a mismatch means candidates were lost or duplicated.
with expected as (
    select count(*) as n from {{ ref('backtest_reach') }} where reach = 'rankable'
),

actual as (
    select strategy, count(*) as n from {{ ref('bt_ranks') }} group by strategy
)

select actual.strategy, actual.n as ranked, expected.n as rankable
from actual
cross join expected
where actual.n <> expected.n
