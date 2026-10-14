-- Systems whose dependencies were scanned (assets.toml), with their exposure
-- and mission impact: the organisation-specific inputs of CISA's tables.
select
    asset,
    location,
    requirements,
    python,
    publicly_exposed,
    mission_impact,
    loaded_at as scanned_at
from {{ source('raw', 'assets') }}
