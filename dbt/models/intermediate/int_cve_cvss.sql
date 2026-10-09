-- One CVSS score per CVE and family (v3, v4, v2), then one headline score.
--
-- Within a family, the score comes from, in order:
--   1. NVD ("Primary"): an independent analyst, the same rules for every vendor;
--   2. the CNA that published the CVE (often the vendor itself);
--   3. any other source (ADPs such as CISA).
-- Ties go to the newer version (3.1 before 3.0), then to the higher score.
--
-- Headline score: v3 first, because most CVEs have one and the usual patching
-- thresholds (7.0 "high", 9.0 "critical") were defined on v3; then v4, then v2.
with scores as (
    select
        cvss.*,
        case
            when cvss.cvss_version in ('3.0', '3.1') then 'v3'
            when cvss.cvss_version = '4.0' then 'v4'
            when cvss.cvss_version = '2.0' then 'v2'
        end as family,
        case
            when cvss.source_type = 'Primary' then 'nvd'
            when cvss.source = cves.source_identifier then 'cna'
            else 'other'
        end as provider
    from {{ ref('stg_nvd__cvss') }} as cvss
    inner join {{ ref('stg_nvd__cves') }} as cves using (cve_id)
),

ranked as (
    select
        *,
        row_number() over (
            partition by cve_id, family
            order by
                case provider when 'nvd' then 1 when 'cna' then 2 else 3 end,
                cvss_version desc,
                base_score desc
        ) as preference
    from scores
),

per_family as (
    select
        cve_id,
        any_value(base_score) filter (where family = 'v3' and preference = 1) as cvss3_score,
        any_value(base_severity) filter (where family = 'v3' and preference = 1) as cvss3_severity,
        any_value(vector) filter (where family = 'v3' and preference = 1) as cvss3_vector,
        any_value(provider) filter (where family = 'v3' and preference = 1) as cvss3_provider,
        any_value(base_score) filter (where family = 'v4' and preference = 1) as cvss4_score,
        any_value(base_severity) filter (where family = 'v4' and preference = 1) as cvss4_severity,
        any_value(provider) filter (where family = 'v4' and preference = 1) as cvss4_provider,
        any_value(base_score) filter (where family = 'v2' and preference = 1) as cvss2_score,
        any_value(base_severity) filter (where family = 'v2' and preference = 1) as cvss2_severity,
        -- NVD and the CNA both scored v3.1 and got different results
        -- (NULL when one of them did not score it).
        max(base_score) filter (where cvss_version = '3.1' and provider = 'nvd')
            <> max(base_score) filter (where cvss_version = '3.1' and provider = 'cna') as cvss3_sources_disagree
    from ranked
    group by cve_id
)

select
    *,
    coalesce(cvss3_score, cvss4_score, cvss2_score) as cvss_score,
    coalesce(cvss3_severity, cvss4_severity, cvss2_severity) as cvss_severity,
    case
        when cvss3_score is not null then '3'
        when cvss4_score is not null then '4'
        when cvss2_score is not null then '2'
    end as cvss_family
from per_family
