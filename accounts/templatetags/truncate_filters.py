from django import template
from django.utils.timesince import timesince
from datetime import datetime

# Filters
register = template.Library()


@register.filter
def get_truncate_content(value, arg):
    if len(value) <= arg:
        return value

    truncated_value = value[:arg]
    last_space_index = truncated_value.rfind(" ")
    if last_space_index > 0:
        truncated_value = truncated_value[:last_space_index]

    return truncated_value + "..."
