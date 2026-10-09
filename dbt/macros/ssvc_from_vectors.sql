{#
    SSVC inputs derived from the CVSS vectors (v3, else v4, else v2) of a row
    with cvss3_vector, cvss4_vector and cvss2_vector columns. Each returns
    true/false, or NULL when the CVE has no vector at all. Checked against
    CISA's own assessments: 92% (automatable) and 90% (total impact) agreement.
#}

{# Automatable: network, low complexity, no privileges, no user interaction. #}
{% macro automatable_from_vectors() -%}
    case
        when cvss3_vector is not null
            then {{ vector_has_all('cvss3_vector', ['AV:N', 'AC:L', 'PR:N', 'UI:N']) }}
        when cvss4_vector is not null
            then {{ vector_has_all('cvss4_vector', ['AV:N', 'AC:L', 'AT:N', 'PR:N', 'UI:N']) }}
        when cvss2_vector is not null
            then {{ vector_has_all('cvss2_vector', ['AV:N', 'AC:L', 'Au:N']) }}
    end
{%- endmacro %}

{# Total technical impact: high (v2: complete) confidentiality and integrity loss. #}
{% macro total_impact_from_vectors() -%}
    case
        when cvss3_vector is not null then {{ vector_has_all('cvss3_vector', ['C:H', 'I:H']) }}
        when cvss4_vector is not null then {{ vector_has_all('cvss4_vector', ['VC:H', 'VI:H']) }}
        when cvss2_vector is not null then {{ vector_has_all('cvss2_vector', ['C:C', 'I:C']) }}
    end
{%- endmacro %}

{% macro vector_source() -%}
    case
        when cvss3_vector is not null then 'cvss3'
        when cvss4_vector is not null then 'cvss4'
        when cvss2_vector is not null then 'cvss2'
    end
{%- endmacro %}
