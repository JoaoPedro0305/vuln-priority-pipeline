-- One line per scanned asset: how many packages, how many are vulnerable, and
-- how urgent the worst finding is.
with findings as (
    select
        asset,
        count(*) as findings,
        count(distinct package) as vulnerable_packages,
        count(*) filter (where in_kev) as in_kev,
        count(*) filter (where ssvc_decision in ('act', 'attend')) as act_or_attend,
        count(*) filter (where fixed_in is null) as without_fix,
        min(remediation_days) as shortest_deadline_days
    from {{ ref('asset_findings') }}
    group by asset
),

packages as (
    select
        asset,
        count(*) as packages,
        count(*) filter (where is_direct) as direct_packages
    from {{ ref('stg_asset_packages') }}
    group by asset
)

select
    assets.asset,
    assets.location,
    assets.publicly_exposed,
    assets.mission_impact,
    coalesce(packages.packages, 0) as packages,
    coalesce(packages.direct_packages, 0) as direct_packages,
    coalesce(findings.vulnerable_packages, 0) as vulnerable_packages,
    coalesce(findings.findings, 0) as findings,
    coalesce(findings.in_kev, 0) as in_kev,
    coalesce(findings.act_or_attend, 0) as act_or_attend,
    coalesce(findings.without_fix, 0) as without_fix,
    findings.shortest_deadline_days,
    assets.scanned_at
from {{ ref('stg_assets') }} as assets
left join packages using (asset)
left join findings using (asset)
