# Frontend guide — Retro Neon design system

Every page shares one look: dark synthwave background, neon cyan/pink/purple
accents, gradient headings, glowing cards. This isn't optional per-page
styling — **all of it lives in `static/css/base.css` and `templates/base.html`,
shared by every app.** New pages should reuse the existing classes, not
invent new colors or components.

**Copy `templates/_page_template.html` when starting a new page** — it
demonstrates every component below with comments. Don't build a page from
scratch.

## Rules

1. Every page template starts with `{% extends "base.html" %}`. Never write
   your own `<html>`/`<head>`/navbar/footer — `base.html` already has fonts,
   the background effects, the navbar, flash messages, and the footer.
2. Put page body content inside one or more `<div class="card">` blocks, not
   loose in `{% block content %}`.
3. Don't hardcode colors (`color: #ff00ff`) in a template's inline styles or
   a new CSS file. Use the CSS custom properties from `base.css` (e.g.
   `var(--neon-pink)`) if you need something the existing component classes
   don't cover — and check whether an existing class already does what you
   want before adding new CSS at all.
4. Reuse badge/button/table/form classes (below) instead of writing new
   ones. If you genuinely need a new component, add it to `base.css` as a
   shared class (`.your-component`), not as one-off inline styles, so
   everyone else can reuse it too.

## Design tokens (`static/css/base.css` `:root`)

| Token | Value | Use for |
|---|---|---|
| `--bg-void` | `#0a0118` | page background |
| `--bg-surface` / `--bg-surface-alt` | `#150a2e` / `#1e0f3d` | card backgrounds |
| `--bg-input` | `#0f0722` | form field backgrounds |
| `--neon-cyan` | `#05f2f2` | links, headings, "active"/success accents |
| `--neon-pink` | `#ff2e97` | brand, primary gradient |
| `--neon-purple` | `#a239ff` | secondary gradient, borders |
| `--neon-yellow` | `#ffe45e` | warnings, "expired" states |
| `--neon-red` | `#ff4365` | danger, "revoked" states |
| `--neon-green` | `#39ff9d` | "active"/success states |
| `--text-primary` / `--text-muted` / `--text-dim` | off-white / lavender-grey / dim purple-grey | body text / secondary text / faint text |
| `--gradient-brand` | cyan → pink | logo, `<h1>` text |
| `--gradient-button` | pink → purple | primary buttons |
| `--font-display` | Orbitron | headings, buttons, badges, nav — uppercase, geometric |
| `--font-body` | Rajdhani | body copy, form labels/inputs |

Both fonts are loaded from Google Fonts in `base.html`'s `<head>` already —
don't add another font import.

## Components

**Cards** — `<div class="card">...</div>`. The standard content container:
dark gradient surface, soft neon border, drop shadow. Nest headings/forms/
tables/buttons inside.

**Headings** — plain `<h1>`/`<h2>` are already styled (gradient-filled `<h1>`,
glowing cyan `<h2>`). Don't add classes to them.

**Buttons** — plain `<button>` or `<a class="btn">` get the pink→purple
gradient automatically. Add `.danger` for destructive actions (delete, ban,
revoke). Add `data-confirm="Some question?"` to any button/link to get a
confirm-dialog before it fires (handled by `static/js/base.js`, no extra JS
needed per-page).

**Forms** — wrap in `<form class="stacked-form">`. Labels and inputs inside
are styled automatically (dark fields, neon focus glow) — don't add classes
to individual fields.

**Badges** — `<span class="badge MODIFIER">Text</span>`. Existing modifiers,
reuse by meaning rather than adding new ones:
- `.active` / `.public` → green, "good" state
- `.expired` / `.role_restricted` → yellow, "caution" state
- `.revoked` / `.private` → red, "blocked/bad" state

**Tables** — plain `<table>`/`<thead>`/`<tbody>` are fully styled (neon
header row, row-hover highlight). No extra classes needed.

**Flash messages** — handled automatically by `base.html` via Django's
messages framework (`messages.success(request, "...")` etc. in a view).
`.error` / `.success` / `.info` tags get red/green/yellow glow borders.

**Helper text** — `<p class="text-muted">` for secondary/explanatory copy.

## Background effects (don't touch unless you mean to)

`body::before` and `body::after` in `base.css` render the ambient glow blobs
and the retro perspective grid at the bottom of the viewport — this is
global and automatic on every page, nothing to add per-template.
