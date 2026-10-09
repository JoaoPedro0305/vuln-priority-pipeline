{#
    Fails unless the model has exactly `expected` rows (e.g. a complete decision table).
#}
{% test row_count(model, expected) %}
select count(*) as row_count
from {{ model }}
having count(*) <> {{ expected }}
{% endtest %}
