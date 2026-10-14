{#
    Every known vulnerability in the dependencies of every asset, with a
    decision for that asset: the same flaw can call for action on an
    internet-facing, high-impact system and wait for the normal cycle on an
    internal batch job.

    CVE facts (KEV, EPSS, exploitation, automatable, technical impact) come from
    cve_priorities. A flaw without a CVE, or with one NVD has not published yet,
    gets automatable and technical impact from the CVSS vector of its OSV
    advisory, and no evidence of exploitation.
#}
with findings as (
    select
        vulns.asset,
        vulns.package,
        vulns.version,
        packages.is_direct,
        vulns.fixed_in,
        vulns.vuln_key,
        case when starts_with(vulns.vuln_key, 'CVE-') then vulns.vuln_key end as cve_id,
        vulns.osv_ids,
        osv.summary,
        osv.cvss3_vector,
        osv.cvss4_vector,
        null::varchar as cvss2_vector,
        assets.publicly_exposed,
        assets.mission_impact
    from {{ ref('stg_asset_vulns') }} as vulns
    inner join {{ ref('stg_asset_packages') }} as packages using (asset, package, version)
    inner join {{ ref('stg_assets') }} as assets using (asset)
    left join {{ ref('stg_osv_vulns') }} as osv using (vuln_key)
),

inputs as (
    select
        findings.*,
        coalesce(priorities.in_kev, false) as in_kev,
        coalesce(priorities.kev_ransomware, false) as kev_ransomware,
        priorities.epss,
        priorities.cvss_score,
        coalesce(priorities.exploitation, 'none') as exploitation,
        coalesce(
            priorities.automatable,
            case {{ automatable_from_vectors() }} when true then 'yes' when false then 'no' end,
            'no'
        ) as automatable,
        coalesce(
            priorities.technical_impact,
            case {{ total_impact_from_vectors() }} when true then 'total' when false then 'partial' end,
            'partial'
        ) as technical_impact
    from findings
    left join {{ ref('cve_priorities') }} as priorities using (cve_id)
),

decisions as (
    select
        inputs.*,
        ssvc.decision as ssvc_decision,
        bod.remediation
    from inputs
    left join {{ ref('ssvc_cisa_coordinator') }} as ssvc
        on ssvc.exploitation = inputs.exploitation
        and ssvc.automatable = inputs.automatable
        and ssvc.technical_impact = inputs.technical_impact
        and ssvc.mission_impact = inputs.mission_impact
    left join {{ ref('bod_26_04_timelines') }} as bod
        on bod.in_kev = case when inputs.in_kev then 'yes' else 'no' end
        and bod.publicly_exposed = inputs.publicly_exposed
        and bod.automatable = inputs.automatable
        and bod.technical_impact = inputs.technical_impact
)

select
    row_number() over (order by {{ priority_order() }}, asset, package, vuln_key) as priority_rank,
    asset,
    package,
    version,
    is_direct,
    fixed_in,
    vuln_key as vuln_id,
    cve_id,
    osv_ids,
    summary,
    ssvc_decision,
    remediation,
    case
        when remediation like '3 days%' then 3
        when remediation = '14 days' then 14
        when remediation = '60 days' then 60
    end as remediation_days,
    concat_ws(
        '; ',
        case
            when in_kev then 'exploited in the wild (KEV' || case when kev_ransomware then ', ransomware)' else ')' end
            when exploitation = 'poc' then 'public exploit'
        end,
        case when automatable = 'yes' then 'automatable' end,
        case when technical_impact = 'total' then 'total control' end,
        case when epss is not null then printf('EPSS %.1f%%', floor(epss * 1000) / 10) end,
        case when cvss_score is not null then 'CVSS ' || cvss_score end,
        case when fixed_in is not null then 'fixed in ' || fixed_in else 'no fix released' end
    ) as priority_reason,
    exploitation,
    automatable,
    technical_impact,
    in_kev,
    epss,
    cvss_score,
    publicly_exposed,
    mission_impact
from decisions
