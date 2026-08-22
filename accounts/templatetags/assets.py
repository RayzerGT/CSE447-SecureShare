"""
accounts/templatetags/assets.py
Shared frontend infrastructure (lives under accounts/ only because Django
discovers template tags from installed apps, and accounts/ is where the rest
of the shared shell scaffolding sits - it is not account-specific).

`{% versioned_static %}` behaves like `{% static %}` but appends the file's
last-modified time as a query string:

    /static/css/base.css?v=1737052800

Browsers cache static files aggressively, so without this a teammate who
pulls a CSS change keeps seeing the old stylesheet until they hard-refresh.
The stamp changes automatically whenever the file changes, so the browser
refetches exactly when it should and keeps caching the rest of the time.
"""

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
