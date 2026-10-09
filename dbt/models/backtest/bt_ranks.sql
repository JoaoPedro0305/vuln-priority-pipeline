{#
    Where each strategy would have placed every CVE that went on to be
    exploited, among all candidates of the same decision date.

    Strategies:
      random    - no information: the floor any strategy must beat
      cvss      - highest CVSS first (the usual "patch criticals first")
      epss      - highest EPSS that day first
      timeline_first   - BOD 26-04 timeline, then SSVC decision, then EPSS:
                         this project's first ranking (dropped)
      track_star_first - act, attend, track*, track, then EPSS: its second
                         ranking (dropped)
      priority  - this project's ranking: act, attend, then EPSS, then CVSS
                  ("in KEV" is always false here), with the inputs known that day

    Ties are broken by md5(cve_id): arbitrary but stable, and it carries no
    information, so no strategy gets an accidental head start.
#}
with ranked as (
    select
        decision_date,
        cve_id,
        exploited,
        count(*) over (partition by decision_date) as candidates,
        row_number() over (partition by decision_date order by md5(cve_id)) as rank_random,
        row_number() over (
            partition by decision_date order by cvss_score desc nulls last, md5(cve_id)
        ) as rank_cvss,
        row_number() over (
            partition by decision_date order by epss desc, md5(cve_id)
        ) as rank_epss,
        row_number() over (
            partition by decision_date
            order by
                {{ remediation_order('remediation') }},
                {{ decision_order('ssvc_decision') }},
                epss desc,
                cvss_score desc nulls last,
                md5(cve_id)
        ) as rank_timeline_first,
        row_number() over (
            partition by decision_date
            order by
                case ssvc_decision when 'act' then 1 when 'attend' then 2 when 'track*' then 3 else 4 end,
                epss desc,
                md5(cve_id)
        ) as rank_track_star_first,
        row_number() over (
            partition by decision_date
            order by {{ priority_order(in_kev='false') }}, md5(cve_id)
        ) as rank_priority
    from {{ ref('bt_candidates') }}
)

unpivot (
    select
        decision_date, cve_id, candidates,
        rank_random, rank_cvss, rank_epss, rank_timeline_first, rank_track_star_first, rank_priority
    from ranked
    where exploited
)
on
    rank_random as 'random',
    rank_cvss as 'cvss',
    rank_epss as 'epss',
    rank_timeline_first as 'timeline_first',
    rank_track_star_first as 'track_star_first',
    rank_priority as 'priority'
into name strategy value rank
