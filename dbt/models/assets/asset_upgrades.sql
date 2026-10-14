-- The work to do, one line per vulnerable package: what to upgrade it to, how
-- many flaws that fixes, and the most urgent decision among them. Ordered by
-- the most urgent finding of each package.
select
    findings.asset,
    findings.package,
    findings.version,
    packages.upgrade_to,
    packages.is_direct,
    count(*) as vulnerabilities,
    count(*) filter (where findings.fixed_in is null) as without_fix,
    count(*) filter (where findings.in_kev) as in_kev,
    arg_min(findings.ssvc_decision, findings.priority_rank) as ssvc_decision,
    min(findings.remediation_days) as deadline_days,
    arg_min(findings.vuln_id, findings.priority_rank) as most_urgent,
    min(findings.priority_rank) as priority_rank
from {{ ref('asset_findings') }} as findings
inner join {{ ref('stg_asset_packages') }} as packages using (asset, package, version)
group by all
