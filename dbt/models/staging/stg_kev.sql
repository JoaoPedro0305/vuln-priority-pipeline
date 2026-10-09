-- KEV catalog with trimmed text (some names carry stray spaces) and the
-- ransomware flag as a boolean.
select
    cve_id,
    trim(vendor_project) as vendor,
    trim(product) as product,
    trim(vulnerability_name) as vulnerability_name,
    date_added,
    due_date,
    trim(short_description) as short_description,
    trim(required_action) as required_action,
    known_ransomware_use = 'Known' as known_ransomware_use,
    cwes as cwe_ids,
    catalog_version
from {{ source('raw', 'kev') }}
