{#
    Fails on every row whose value falls outside [min_value, max_value].
    NULLs pass: whether a column may be NULL is the not_null test's job.
#}
{% test values_between(model, column_name, min_value, max_value) %}
select {{ column_name }}
from {{ model }}
where {{ column_name }} < {{ min_value }} or {{ column_name }} > {{ max_value }}
{% endtest %}
