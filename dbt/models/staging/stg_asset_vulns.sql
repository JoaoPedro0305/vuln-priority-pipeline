-- One row per (asset, package, flaw), with the first version that fixes it.
select asset, package, version, vuln_key, osv_ids, fixed_in
from {{ source('raw', 'asset_vulns') }}
