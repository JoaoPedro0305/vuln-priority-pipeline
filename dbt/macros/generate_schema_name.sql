{#
    By default dbt prefixes custom schemas with the target schema ("main_staging").
    Use the layer name as is: staging, intermediate, marts.
#}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {{ custom_schema_name if custom_schema_name else target.schema }}
{%- endmacro %}
