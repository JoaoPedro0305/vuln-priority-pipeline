-- Findings that warrant a GitHub issue: on an asset with alerts on, a flaw CISA
-- lists as exploited in the wild (KEV), or one whose SSVC decision for that
-- asset is "act". One row per (asset, package, flaw); alert_key identifies the
-- issue across runs, so it is opened once and closed when the flaw is gone.
select
    findings.asset || '|' || findings.package || '|' || findings.vuln_id as alert_key,
    findings.asset,
    findings.package,
    findings.version,
    packages.upgrade_to,
    findings.fixed_in,
    findings.vuln_id,
    findings.cve_id,
    findings.summary,
    findings.in_kev,
    cves.kev_date_added,
    findings.ssvc_decision,
    findings.remediation,
    findings.remediation_days,
    findings.epss,
    findings.priority_reason,
    findings.priority_rank
from {{ ref('asset_findings') }} as findings
inner join {{ ref('stg_assets') }} as assets using (asset)
inner join {{ ref('stg_asset_packages') }} as packages using (asset, package, version)
left join {{ ref('cves') }} as cves using (cve_id)
where assets.alerts
    and (findings.in_kev or findings.ssvc_decision = 'act')
