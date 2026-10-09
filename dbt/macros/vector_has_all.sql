{#
    True when a CVSS vector contains every metric in `metrics`, e.g.
    vector_has_all('cvss3_vector', ['AV:N', 'PR:N']).

    The vector is wrapped in slashes and each metric searched as "/AV:N/", so
    "AV:N" does not match inside "MAV:N" (a different CVSS 4.0 metric) and the
    v2 format, which has no "CVSS:x/" prefix, works the same way.
#}
{% macro vector_has_all(column, metrics) -%}
    (
    {%- for metric in metrics %}
        contains('/' || {{ column }} || '/', '/{{ metric }}/'){% if not loop.last %} and{% endif %}
    {%- endfor %}
    )
{%- endmacro %}
