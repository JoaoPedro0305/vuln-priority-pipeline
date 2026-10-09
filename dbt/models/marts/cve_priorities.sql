{#
    Patching priority of every published CVE, from CISA's two decision tables:

    - SSVC (CISA Coordinator): exploitation x automatable x technical impact x
      mission impact -> track, track*, attend or act.
    - BOD 26-04: in KEV x publicly exposed x automatable x technical impact ->
      a remediation timeline (3 days with forensics, 3, 14 or 60 days, next upgrade).

    Inputs come from CISA's own SSVC assessment when there is one (about half of
    all CVEs) and are otherwise derived from KEV, NVD references and the CVSS
    vector. Mission impact and public exposure describe the organisation, not
    the vulnerability: they are dbt variables (see dbt_project.yml).

    priority_rank orders everything: remediation timeline, then SSVC decision,
    then EPSS, then CVSS.
#}

{%- set mission_impact = var('mission_impact') -%}
{%- set publicly_exposed = var('publicly_exposed') -%}
{%- if mission_impact not in ['low', 'medium', 'high'] -%}
    {{ exceptions.raise_compiler_error("var mission_impact must be low, medium or high, got: " ~ mission_impact) }}
{%- endif -%}
{%- if publicly_exposed not in ['yes', 'no'] -%}
    {{ exceptions.raise_compiler_error("var publicly_exposed must be yes or no, got: " ~ publicly_exposed) }}
{%- endif -%}

with derived as (
    select
        *,
        case
            when in_kev then 'active'
            when has_exploit_reference then 'poc'
            else 'none'
        end as derived_exploitation,

        -- Automatable: reachable over the network, low complexity, no
        -- privileges, no user interaction. Agrees with CISA on 92% of CVEs.
        case
            when cvss3_vector is not null
                then {{ vector_has_all('cvss3_vector', ['AV:N', 'AC:L', 'PR:N', 'UI:N']) }}
            when cvss4_vector is not null
                then {{ vector_has_all('cvss4_vector', ['AV:N', 'AC:L', 'AT:N', 'PR:N', 'UI:N']) }}
            when cvss2_vector is not null
                then {{ vector_has_all('cvss2_vector', ['AV:N', 'AC:L', 'Au:N']) }}
        end as derived_automatable,

        -- Total technical impact: high (v2: complete) confidentiality and
        -- integrity loss, i.e. control of the component. Agrees with CISA on 90%.
        case
            when cvss3_vector is not null then {{ vector_has_all('cvss3_vector', ['C:H', 'I:H']) }}
            when cvss4_vector is not null then {{ vector_has_all('cvss4_vector', ['VC:H', 'VI:H']) }}
            when cvss2_vector is not null then {{ vector_has_all('cvss2_vector', ['C:C', 'I:C']) }}
        end as derived_total_impact,

        case
            when cvss3_vector is not null then 'cvss3'
            when cvss4_vector is not null then 'cvss4'
            when cvss2_vector is not null then 'cvss2'
        end as vector_source
    from {{ ref('cves') }}
),

inputs as (
    select
        *,
        -- The strongest evidence wins: CISA's assessment can predate the CVE's
        -- addition to KEV, and NVD can know of an exploit CISA did not record.
        case
            when 'active' in (ssvc_exploitation, derived_exploitation) then 'active'
            when 'poc' in (ssvc_exploitation, derived_exploitation) then 'poc'
            else 'none'
        end as exploitation,
        case
            when in_kev then 'kev'
            when ssvc_exploitation in ('poc', 'active') then 'cisa'
            when has_exploit_reference then 'nvd exploit reference'
            else 'no evidence'
        end as exploitation_evidence,

        coalesce(
            ssvc_automatable,
            case derived_automatable when true then 'yes' when false then 'no' end,
            'no'
        ) as automatable,
        case
            when ssvc_automatable is not null then 'cisa'
            when derived_automatable is not null then vector_source
            else 'unknown'
        end as automatable_source,

        coalesce(
            ssvc_technical_impact,
            case derived_total_impact when true then 'total' when false then 'partial' end,
            'partial'
        ) as technical_impact,
        case
            when ssvc_technical_impact is not null then 'cisa'
            when derived_total_impact is not null then vector_source
            else 'unknown'
        end as technical_impact_source
    from derived
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
        and ssvc.mission_impact = '{{ mission_impact }}'
    left join {{ ref('bod_26_04_timelines') }} as bod
        on bod.in_kev = case when inputs.in_kev then 'yes' else 'no' end
        and bod.publicly_exposed = '{{ publicly_exposed }}'
        and bod.automatable = inputs.automatable
        and bod.technical_impact = inputs.technical_impact
)

select
    cve_id,
    row_number() over (
        order by
            case remediation
                when '3 days & forensic investigation' then 1
                when '3 days' then 2
                when '14 days' then 3
                when '60 days' then 4
                else 5
            end,
            case ssvc_decision when 'act' then 1 when 'attend' then 2 when 'track*' then 3 else 4 end,
            epss desc nulls last,
            cvss_score desc nulls last,
            published desc,
            cve_id
    ) as priority_rank,
    remediation,
    case
        when remediation like '3 days%' then 3
        when remediation = '14 days' then 14
        when remediation = '60 days' then 60
    end as remediation_days,
    remediation like '%forensic%' as forensic_investigation,
    ssvc_decision,
    concat_ws(
        '; ',
        case
            when in_kev then 'exploited in the wild (KEV' || case when kev_ransomware then ', ransomware)' else ')' end
            when exploitation = 'poc' then 'public exploit (' || exploitation_evidence || ')'
        end,
        case when automatable = 'yes' then 'automatable' end,
        case when technical_impact = 'total' then 'total control' end,
        -- Truncated, not rounded: 0.99999 reads 99.9%, not a certain 100%.
        case when epss is not null then printf('EPSS %.1f%%', floor(epss * 1000) / 10) end,
        case when cvss_score is not null then 'CVSS ' || cvss_score end
    ) as priority_reason,
    exploitation,
    exploitation_evidence,
    automatable,
    automatable_source,
    technical_impact,
    technical_impact_source,
    in_kev,
    kev_ransomware,
    epss,
    epss_percentile,
    cvss_score,
    cvss_severity,
    cvss3_provider,
    vendor,
    product,
    published
from decisions
