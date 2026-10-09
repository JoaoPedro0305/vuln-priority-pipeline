{#
    Not every KEV addition can be caught by a monthly patching cycle. Each one
    added during a backtest window is classified by why a strategy could, or
    could not, have ranked it on that window's decision date.
#}
select
    dates.decision_date,
    kev.cve_id,
    kev.date_added,
    case
        when cves.cve_id is null then 'not in NVD or rejected'
        when cves.published >= dates.decision_date then 'published after the decision date'
        when epss.cve_id is null then 'not scored by EPSS that day'
        else 'rankable'
    end as reach
from {{ ref('stg_kev') }} as kev
inner join {{ ref('bt_decision_dates') }} as dates
    on kev.date_added >= dates.decision_date and kev.date_added < dates.window_end
left join {{ ref('cves') }} as cves using (cve_id)
left join {{ ref('stg_epss') }} as epss
    on epss.cve_id = kev.cve_id and epss.score_date = dates.decision_date
