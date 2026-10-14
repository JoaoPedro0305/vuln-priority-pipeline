-- Every package each asset would install, transitive ones included, and the
-- version that fixes all its known vulnerabilities (computed at scan time,
-- where versions are compared by Python's rules, not as text).
select asset, package, version, is_direct, upgrade_to
from {{ source('raw', 'asset_packages') }}
