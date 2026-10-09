-- SSVC decision points assessed for a CVE, mostly by CISA's "Vulnrichment"
-- program (role "CISA Coordinator"). The options list holds one object per
-- decision point: [{"exploitation": "poc"}, {"automatable": "no"}, {"technicalImpact": "partial"}].
with entries as (
    select
        nvd.cve_id,
        unnest(cast(nvd.metrics -> 'ssvcV203' as json[])) as entry
    from {{ source('raw', 'nvd') }} as nvd
    where (nvd.metrics -> 'ssvcV203') is not null
),

options as (
    select
        cve_id,
        entry ->> 'source' as source,
        entry -> 'ssvcData' ->> 'role' as role,
        entry -> 'ssvcData' ->> 'version' as ssvc_version,
        -- "2025-05-08T17:26:03.797789Z": the cast drops the Z and keeps UTC.
        cast(entry -> 'ssvcData' ->> 'timestamp' as timestamp) as assessed_at,
        cast(entry -> 'ssvcData' -> 'options' as json[]) as options
    from entries
)

select
    cve_id,
    source,
    role,
    ssvc_version,
    assessed_at,
    [o ->> 'exploitation' for o in options if (o ->> 'exploitation') is not null][1] as exploitation,
    [o ->> 'automatable' for o in options if (o ->> 'automatable') is not null][1] as automatable,
    [o ->> 'technicalImpact' for o in options if (o ->> 'technicalImpact') is not null][1] as technical_impact
from options
