{#
    Every CVE a team could have chosen to patch on each decision date, with only
    what was known on that date:

    - published before the date, not rejected, scored by EPSS that day;
    - not yet in KEV (already-known exploitation is not a prediction);
    - EPSS score of that day, not today's;
    - CISA's SSVC assessment only if made before the date (NVD's "Exploit"
      reference tags have no date, so they are not used at all);
    - automatable / technical impact otherwise derived from the CVSS vector.

    Known limitation: CVSS scores and vectors are today's. They change much less
    than EPSS, but a few CVEs were scored (or re-scored) after the date.

    `exploited`: the CVE entered KEV within the window after the decision date.
#}

{%- set mission_impact = var('mission_impact') -%}
{%- set publicly_exposed = var('publicly_exposed') -%}

with scored as (
    select
        dates.decision_date,
        dates.window_end,
        epss.cve_id,
        epss.epss
    from {{ ref('bt_decision_dates') }} as dates
    inner join {{ ref('stg_epss') }} as epss on epss.score_date = dates.decision_date
),

known as (
    select
        scored.*,
        cves.published,
        cves.cvss_score,
        kev.date_added as kev_date_added,
        cves.ssvc_assessed_at < scored.decision_date as cisa_assessed,
        cves.ssvc_exploitation,
        cves.ssvc_automatable,
        cves.ssvc_technical_impact,
        {{ automatable_from_vectors() }} as derived_automatable,
        {{ total_impact_from_vectors() }} as derived_total_impact
    from scored
    inner join {{ ref('cves') }} as cves using (cve_id)
    left join {{ ref('stg_kev') }} as kev using (cve_id)
    where cves.published < scored.decision_date
        and (kev.date_added is null or kev.date_added >= scored.decision_date)
),

inputs as (
    select
        *,
        case
            when cisa_assessed and ssvc_exploitation in ('poc', 'active') then ssvc_exploitation
            else 'none'
        end as exploitation,
        case
            when cisa_assessed then ssvc_automatable
            when derived_automatable then 'yes'
            else 'no'
        end as automatable,
        case
            when cisa_assessed then ssvc_technical_impact
            when derived_total_impact then 'total'
            else 'partial'
        end as technical_impact
    from known
)

select
    inputs.decision_date,
    inputs.cve_id,
    inputs.epss,
    inputs.cvss_score,
    inputs.exploitation,
    inputs.automatable,
    inputs.technical_impact,
    ssvc.decision as ssvc_decision,
    bod.remediation,
    inputs.kev_date_added,
    coalesce(inputs.kev_date_added < inputs.window_end, false) as exploited
from inputs
left join {{ ref('ssvc_cisa_coordinator') }} as ssvc
    on ssvc.exploitation = inputs.exploitation
    and ssvc.automatable = inputs.automatable
    and ssvc.technical_impact = inputs.technical_impact
    and ssvc.mission_impact = '{{ mission_impact }}'
left join {{ ref('bod_26_04_timelines') }} as bod
    on bod.in_kev = 'no'
    and bod.publicly_exposed = '{{ publicly_exposed }}'
    and bod.automatable = inputs.automatable
    and bod.technical_impact = inputs.technical_impact
