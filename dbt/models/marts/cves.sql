-- One row per published (not rejected) CVE with everything known about it:
-- severity, weakness, products, exploitation evidence and EPSS.
select
    cves.cve_id,
    cves.published,
    cves.last_modified,
    cves.vuln_status,
    cves.description,
    cves.cve_tags,

    -- Severity
    cvss.cvss_score,
    cvss.cvss_severity,
    cvss.cvss_family,
    cvss.cvss3_score,
    cvss.cvss3_severity,
    cvss.cvss3_vector,
    cvss.cvss3_provider,
    cvss.cvss3_sources_disagree,
    cvss.cvss4_score,
    cvss.cvss4_severity,
    cvss.cvss2_score,

    -- What and where
    coalesce(weak.cwe_ids, kev.cwe_ids, []) as cwe_ids,
    coalesce(kev.vendor, prod.main_vendor) as vendor,
    coalesce(kev.product, prod.main_product) as product,
    coalesce(prod.products, []) as products,

    -- Exploitation evidence
    kev.cve_id is not null as in_kev,
    kev.date_added as kev_date_added,
    kev.due_date as kev_due_date,
    coalesce(kev.known_ransomware_use, false) as kev_ransomware,
    coalesce(refs.has_exploit_reference, false) as has_exploit_reference,
    coalesce(refs.has_patch_reference, false) as has_patch_reference,
    ssvc.ssvc_exploitation,
    ssvc.ssvc_automatable,
    ssvc.ssvc_technical_impact,
    ssvc.ssvc_assessed_at,

    -- Likelihood
    epss.epss,
    epss.epss_percentile,
    epss.epss_date
from {{ ref('stg_nvd__cves') }} as cves
left join {{ ref('int_cve_cvss') }} as cvss using (cve_id)
left join {{ ref('int_cve_weaknesses') }} as weak using (cve_id)
left join {{ ref('int_cve_products') }} as prod using (cve_id)
left join {{ ref('int_cve_references') }} as refs using (cve_id)
left join {{ ref('int_cve_ssvc') }} as ssvc using (cve_id)
left join {{ ref('int_epss_latest') }} as epss using (cve_id)
left join {{ ref('stg_kev') }} as kev using (cve_id)
where not cves.is_rejected
