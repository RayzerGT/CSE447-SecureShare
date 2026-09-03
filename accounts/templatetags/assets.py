from django import template
from django.contrib.staticfiles import finders
from django.templatetags.static import static
from pathlib import Path

register = template.Library()

@register.simple_tag
def versioned_static(path: str) -> str:
    url = static(path)
    absolute_path = finders.find(path)
    if absolute_path:
        try:
            stamp = int(Path(absolute_path).stat().st_mtime)
        except OSError:
            return url
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}v={stamp}"
    return url
