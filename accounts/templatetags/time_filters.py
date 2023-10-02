from django import template
from django.utils.timesince import timesince
from datetime import datetime

# Filters
register = template.Library()


@register.filter
def get_time_since(value):
    if not isinstance(value, datetime):
        value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')

    return timesince(value) + ' ago'
