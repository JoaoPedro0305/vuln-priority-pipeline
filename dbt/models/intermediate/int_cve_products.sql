-- Affected vendors and products, from the vulnerable CPE strings:
--   cpe:2.3:<part>:<vendor>:<product>:<version>:...
-- part: a = application, o = operating system, h = hardware.
with cpes as (
    select
        cve_id,
        split_part(cpe, ':', 4) as vendor,
        split_part(cpe, ':', 5) as product
    from {{ ref('stg_nvd__cves') }},
        unnest(cpes) as t (cpe)
),

pairs as (
    select
        cve_id,
        vendor,
        product,
        count(*) as cpe_count
    from cpes
    group by all
)

select
    cve_id,
    list_sort(list(vendor || ':' || product)) as products,
    -- The pair with the most CPE entries names the CVE when there is no better
    -- label (KEV's); ties are broken alphabetically so the result is stable.
    first(vendor order by cpe_count desc, vendor, product) as main_vendor,
    first(product order by cpe_count desc, vendor, product) as main_product,
    count(*) as product_count
from pairs
group by cve_id
