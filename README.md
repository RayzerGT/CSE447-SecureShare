# SecureShare

CSE447 project (BRACU_flex, Group 05) — a security-first, Instagram-like
photo sharing app. This is the full skeleton: routing, models, views, and
templates for every feature are wired up and runnable, but the graded
cryptographic/security internals (custom RSA/ECC, hashing+salting, 2FA, RBAC
decision logic, secure session tokens, MAC) are intentionally left as
clearly marked `TODO(<name>):` stubs.

**New here? Start with `SETUP.md`** — a short numbered checklist to get the
app running on your machine. This file has the fuller reference/explanation.

**Building any UI?** See `FRONTEND.md` — the whole site shares one dark
retro-neon design system (shared CSS + component classes), and every new
page must follow it. Copy `templates/_page_template.html` to start a new
page rather than writing HTML from scratch.

**See `todo.txt` in this same folder for exactly who is building what** —
task ownership doesn't follow app boundaries exactly (e.g. `accounts/` is
split between two people; `posts/` is split between two different people).
Grep your own name to find your work:

```bash
grep -rn "TODO(Afnan Satter)" .
grep -rn "TODO(Mos. Mahabuba Akter Munia)" .
grep -rn "TODO(Razeen Hassan)" .
```

Registration and login are fully functional and backed by a real MySQL
database: registering writes rows to `auth_user`, `accounts_profile`, and
`accounts_twofactorsettings`; logging in authenticates against the stored
(hashed) password and writes/updates an `accounts_activesession` row.

## Session management

Implemented and enforced (not just a UI mockup): once a user logs in, a
session is started that ends **5 minutes later** (configurable), regardless
of activity (absolute timeout, not idle/sliding).

1. **`accounts.models.ActiveSession`** gets `expires_at = login time +
   SESSION_TIMEOUT_MINUTES` (env var — see `.env`, currently `5`).
2. **`accounts.security.session_manager.SecureSessionMiddleware`** checks
   every authenticated request against that timestamp. Once it's passed, it
   marks the session revoked in the database, force-logs the user out
   server-side, and shows a "Your session expired after N minute(s)" message.

This is deliberately decoupled from Django's own `SESSION_COOKIE_AGE` (kept
at a generous 1 day as a ceiling) via a separate `SESSION_TIMEOUT_MINUTES` /
`APP_SESSION_TIMEOUT_SECONDS` setting, so the enforced cutoff is something
*this app* controls, not an incidental side effect of the browser cookie
expiring on its own.

The account security dashboard (`/accounts/sessions/`) lists each session's
expiry time and live status (Active / Expired / Revoked).

## Shared team database

**Live and confirmed working:** a central MySQL 8.4 database is hosted on
Aiven (free tier). All three of you should point at this **same** database
(not separate local ones) so you see each other's test data and avoid
migration-drift between machines. All migrations are already applied to it.

The real host/port/username/password are deliberately **not** written down
here or anywhere else in this repo (avoid publishing live infrastructure
endpoints, even to a private repo) — get them from a teammate directly
(chat/DM), and drop them into your own local `.env`, copied from
`.env.example`. `.env` is gitignored; it should be the only place these
values ever live on disk.

Aiven requires an encrypted connection - keep `MYSQL_SSL_MODE=REQUIRED` in
your `.env` for this database (no certificate file needed; verified working
with `mysqlclient`). Don't remove it.

If you're working offline or the shared DB is unreachable, you can point
`.env` at a local MySQL/MariaDB instance instead — the app doesn't care
which one it's talking to, only the `.env` values change. If your local
server doesn't have SSL configured, set `MYSQL_SSL_MODE=` (empty) too. Just
remember to switch back to the shared DB before pushing anything that
depends on shared state.

## System requirements

`requirements.txt` pins exact Python package versions; `.env.example` lists
every environment variable the app reads. Nothing else is required beyond
what's below.

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.13 (tested on 3.13.3) | 3.10+ should work |
| pip packages | see `requirements.txt` | exact versions pinned for reproducibility |
| MySQL or MariaDB server | MySQL 8.0+, or MariaDB 10.4+ | see version note below |
| OS | Windows, macOS, or Linux | only the DB-driver install step differs (below) |

**Django / MariaDB version compatibility:** `requirements.txt` pins
`Django==5.0.14` because the reference dev environment used MariaDB 10.4.32,
and Django 5.1+ raises the minimum supported MariaDB version to 10.5. If the
shared database is MySQL 8.0+ or MariaDB 10.5+, you can safely relax that
pin to a newer Django 5.x release.

**Installing mysqlclient (the Python↔MySQL driver) per OS:**
- **Windows:** `pip install -r requirements.txt` just works — a prebuilt
  wheel is available, no compiler or extra setup needed.
- **macOS:** install the MySQL client libraries first (`brew install mysql-client
  pkg-config`), then `pip install -r requirements.txt`. You may need
  `export PKG_CONFIG_PATH="/opt/homebrew/opt/mysql-client/lib/pkgconfig"`
  (Apple Silicon) or the Intel-equivalent path first if pip can't find them.
- **Linux (Debian/Ubuntu):** `sudo apt install default-libmysqlclient-dev build-essential pkg-config`
  first, then `pip install -r requirements.txt`.
- If you'd rather avoid native build dependencies entirely, `mysqlclient`
  can be swapped for the pure-Python `pymysql` package (`pip install pymysql`,
  then add `import pymysql; pymysql.install_as_MySQLdb()` to the top of
  `secureshare/__init__.py`).

## Setup (each teammate, on their own machine)

1. **Python env + dependencies**
   ```bash
   python -m venv .venv
   ```
   Activate it — Windows: `.venv\Scripts\activate`; macOS/Linux: `source .venv/bin/activate` — then:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env   # Windows: copy .env.example .env
   ```
   Fill in `SECRET_KEY` (any long random string —
   `python -c "import secrets; print(secrets.token_urlsafe(50))"` generates
   one) and the `MYSQL_*` values for the shared database (see "Shared team
   database" above).

3. **Migrate & run**
   ```bash
   python manage.py migrate
   python manage.py createsuperuser   # optional, for /django-admin/
   python manage.py runserver
   ```

4. Visit `http://127.0.0.1:8000/accounts/register/` to create an account,
   then log in at `http://127.0.0.1:8000/accounts/login/`.

Migrations are already generated and committed for every app — no need to
run `makemigrations` unless you change a model.

## Project layout

```
secureshare/   Django project settings/urls (the config package, not an app)
accounts/      Login, Registration, 2FA, session management, profile
crypto_core/   RSA, ECC, Key Management Module, MAC, encryption facade
posts/         Photo feed: creation, visibility, encryption
messaging/     Encrypted 1-on-1 direct messages
social/        Likes and comments
moderation/    RBAC core, admin panel, audit log, user/role management,
               content moderation
templates/, static/  shared UI shell (base.html, navbar, css, js)
templates/_page_template.html  copy this to start any new page
todo.txt       per-member task breakdown - the authoritative ownership doc
SETUP.md       short numbered setup checklist (start here on a new machine)
FRONTEND.md    the design system - read before building any UI
```

`todo.txt` has the real detail (down to which function in which file); the
list above is just the map of apps to feature areas.

## Notes

- All from-scratch crypto requirements (RSA, ECC, password hashing, MAC)
  must NOT use built-in framework or library implementations.
- Input sanitization / XSS protection for comments was considered and
  dropped from scope (it was only in the team's own project proposal, not
  the graded requirements doc) — see `todo.txt`'s notes section.
- Run `python manage.py check` after any change to catch config/model errors early.
- If you restart `manage.py runserver` and your code changes don't seem to
  take effect, check for a stale old server process still bound to port 8000
  and kill it. Windows: `netstat -ano | findstr :8000`; macOS/Linux: `lsof -i :8000`.
