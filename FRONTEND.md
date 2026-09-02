# Frontend guide — SecureShare design system

The whole UI shares one stylesheet and one page shell: **`static/css/base.css`
and `templates/base.html`.** New pages reuse the existing classes — they don't
invent new colors, fonts, or components.

There are **two skins**, both defined in that one stylesheet:

| Skin | Who sees it | Look |
|---|---|---|
| **Social** (default) | Standard Users | Instagram-inspired: white/near-black surfaces, blue primary buttons, brand-gradient avatar rings, script wordmark |
| **Console** (`<body class="console">`) | Admins & Developers | Dark slate dashboard: KPI tiles, dense tables, no gradients |

`base.html` adds the `console` class automatically based on the signed-in
user's role, so **you never set it yourself.** The split is deliberate: a
privileged panel should never look like the social site. It's cosmetic only —
the real wall is `moderation/permissions.py::RoleAccessMiddleware`.

**Copy `templates/_page_template.html` when starting a new page.** It
demonstrates every component below with comments.

## Rules

1. Every page starts with `{% extends "base.html" %}`. Never write your own
   `<html>`/`<head>`/nav — `base.html` has the fonts, shell, role-aware
   navigation and flash messages.
2. Don't hardcode colors (`color: #ff00ff`) in templates or new CSS files. Use
   the tokens below (e.g. `var(--blue)`). Both skins are just different token
   values, so a page built on tokens works in either one for free.
3. Reuse the component classes below. If you genuinely need a new component,
   add it to `base.css` as a shared class, not as one-off inline styles.
4. Never pass a template context variable named **`messages`** — that name
   belongs to Django's flash-message framework, and using it makes your data
   render as flash banners. (`messaging/views.py` uses `thread_messages`.)

## Layout

`base.html` renders a fixed left rail plus a content column:

```
{% block container_class %}{% endblock %}   → max-width 935px (default)
{% block container_class %}narrow{% endblock %}  → 470px  (feed, lists, forms)
{% block container_class %}wide{% endblock %}    → 1200px (tables, DM, dashboards)
```

The rail is responsive on its own — full labels ≥1264px, icon-only 768–1263px,
and a bottom tab bar below 768px. You don't need to do anything for that.

**Signed-out pages** (login, register, 2FA, portal login) hide the rail and
center a card:

```django
{% block chrome %}{% endblock %}
{% block main_class %}app-main--auth{% endblock %}
```

## Design tokens (`base.css` `:root`)

| Token | Social value | Use for |
|---|---|---|
| `--bg` | `#fafafa` | page background |
| `--surface` | `#ffffff` | cards, posts, rail |
| `--surface-alt` / `--surface-hover` | `#fafafa` / `#f2f2f2` | insets, hover states |
| `--border` | `#dbdbdb` | every hairline |
| `--text` / `--text-secondary` / `--text-tertiary` | `#262626` / `#737373` / `#a8a8a8` | body / secondary / timestamps |
| `--blue` | `#0095f6` | primary buttons, links-as-actions |
| `--red` | `#ed4956` | likes, destructive actions, badges |
| `--gradient-brand` | orange→purple | wordmark, avatar story rings |
| `--radius` / `--radius-pill` | `8px` / `999px` | corners |

Dark mode is automatic via `prefers-color-scheme` — it only re-defines these
tokens, so **nothing else in your CSS needs a dark-mode branch.** The console
skin works the same way (`body.console` re-defines the same names).

## Components

### Avatars

Never write an `<img>` for a user — the partial handles the missing-avatar
fallback (a letter tile), so no page renders a broken image:

```django
{% include "_avatar.html" with u=post.owner %}            {# 32px default #}
{% include "_avatar.html" with u=friend size="lg" %}      {# sm|md|lg|xl #}
{% include "_avatar.html" with u=user ring=1 %}           {# gradient story ring #}
```

### Buttons

```html
<button>Primary</button>                      <!-- blue -->
<button class="secondary">Secondary</button>  <!-- grey -->
<button class="danger">Report</button>        <!-- red text, transparent -->
<button class="solid-danger">Ban</button>     <!-- solid red -->
<button class="ghost">Post</button>           <!-- bare blue text -->
<button class="sm">Compact</button>           <!-- for table/ticket rows -->
<button class="block">Full width</button>
<button class="iconbtn"><svg …></svg></button><!-- bare icon (heart, send…) -->
```

Add `data-confirm="Are you sure?"` to any destructive control — `base.js`
wires the confirm dialog, no extra JS needed.

### Content blocks

- `.card` — the standard panel. `.card.flush` removes padding for tables/lists.
- `.post` — a feed post (`.post__head`, `.post__media`, `.post__actions`, `.post__body`).
- `.user-row` — one person in a list (search results, friends, DM list).
- `.post-grid` / `.post-tile` — the 3-up profile grid with a hover stats overlay.
- `.empty-state` — icon + heading + explanation, for "no posts yet" cases.
- `.dev-note` — amber-bordered box for `TODO(Name):` stubs. Use this instead of
  `.text-muted` so a scaffolding note never reads as real product copy.
- `.stat-grid` / `.stat` — console KPI tiles.
- `.ticket` — a report card; add `.ticket--post|--user|--message` for the
  color-coded left border.

### Forms

Wrap in `<form class="stacked-form">`; labels and fields style themselves, and
`{{ form.as_p }}` works as-is. `.search-bar` is the rounded search input with a
leading magnifier icon.

### Icons

Inline SVGs, stroke-based, `viewBox="0 0 24 24"`, `fill="none"`,
`stroke="currentColor"`. They inherit size and color from `.iconbtn` /
`.navlink`. Copy an existing one from `templates/navbar.html` rather than
pulling in an icon library — the project ships no external JS/CSS.

## Static files and caching

`base.html` loads CSS/JS through `{% versioned_static %}`
(`accounts/templatetags/assets.py`), which appends the file's modified time:

```
/static/css/base.css?v=1737052800
```

That means **you don't need to hard-refresh after pulling a CSS change** — the
URL changes with the file, so the browser refetches exactly when it should.
Use `{% versioned_static %}` (not `{% static %}`) for any new stylesheet or
script you add.
