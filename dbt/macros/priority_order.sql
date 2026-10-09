{#
    Sort keys of the priority ranking, shared by cve_priorities and the backtest
    so both rank exactly the same way:

      1. known exploitation (in KEV)
      2. CISA SSVC decisions that call for action out of the normal cycle:
         act, then attend. track and track* both mean "standard timelines"
         (track* only adds "watch closely") and rank together.
      3. EPSS, then CVSS

    Two earlier orders are kept in the backtest to show why they were dropped:
    the BOD 26-04 timeline first (impact before likelihood) and track* ahead of
    track (CISA's many "public PoC" assessments since 2025 then pushed high-EPSS
    CVEs down; none of those track* CVEs entered KEV within a month).
#}
{% macro priority_order(in_kev='in_kev', decision='ssvc_decision', epss='epss', cvss='cvss_score') -%}
    {{ in_kev }} desc,
    {{ decision_order(decision) }},
    {{ epss }} desc nulls last,
    {{ cvss }} desc nulls last
{%- endmacro %}

{% macro decision_order(column) -%}
    case {{ column }} when 'act' then 1 when 'attend' then 2 else 3 end
{%- endmacro %}

{# Only for the backtest's "timeline_first" strategy, kept to document why it was dropped. #}
{% macro remediation_order(column) -%}
    case {{ column }}
        when '3 days & forensic investigation' then 1
        when '3 days' then 2
        when '14 days' then 3
        when '60 days' then 4
        else 5
    end
{%- endmacro %}
