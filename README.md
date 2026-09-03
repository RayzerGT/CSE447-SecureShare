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

## RBAC: roles, permissions, and the single login

Three roles (`accounts.models.Role`): Standard User, Admin, and Developer -
hierarchy Developer > Admin > User, but **not** in the sense of "higher
role can do everything a lower role can." Each role is walled off to
*only* its own area:

- **Standard User** — the social site (feed/upload/messaging/social). No
  access to `/moderation/` or `/portal/`.
- **Admin** — `/moderation/` only. No feed/upload/messaging, no `/portal/`.
  Can lock/suspend/ban **Standard User accounts only** — cannot touch
  other Admin or Developer accounts, and cannot create new admins.
- **Developer** — `/portal/` only. No feed/upload/messaging, no
  `/moderation/`. Two separate menus: grant/revoke the Admin role, and
  separately lock/suspend/ban Standard User accounts (the same power
  Admins have over users) — kept apart from each other.

This is enforced twice over: `moderation.permissions.RoleAccessMiddleware`
redirects Admin/Developer accounts away from anything outside their own
area (so it's not just hidden nav links — the routes themselves are
blocked), and every management view scopes its queryset/target lookup by
role, so even a hand-crafted POST against the right URL gets a 404 if the
target account is the wrong role. Both were verified live, not just
written: an Admin session was confirmed blocked from the feed, upload,
messaging, *and* the developer portal; a Developer session was confirmed
blocked from the feed/upload/messaging and the admin panel; and a crafted
request to ban an Admin account through the Admin's own user-management
endpoint was confirmed to 404 rather than silently succeed.

Admin and Developer are separate privilege tiers, neither implying the
other. **Each account holds exactly one role, by design** — an account is a
Standard User, an Admin, or a Developer, and stays that one thing. Someone
who needs two sets of powers gets two accounts. That single-role rule is
what makes one shared login page possible (below).

- **One login page — `/accounts/login/`** — used by every account,
  whatever its role. There is no separate admin/developer portal login.
  On success, the account's single role decides where it lands
  (`moderation.permissions.home_url_for`). Sharing the page does not widen
  anyone's access: the permission matrix and `RoleAccessMiddleware` still
  govern what each role can reach.
- **2FA** applies to Standard Users only; Admin and Developer accounts
  skip it and go straight to their panel.
- **Admins** land on `/moderation/` — dashboard (total/banned/suspended
  user counts, active sessions, pending reports), user management
  (lock/suspend/ban Standard Users only), content moderation, and a
  **Reports** menu showing posts regular users have flagged
  (`/moderation/reports/`) with delete-post / dismiss actions.
- **Developers** land on `/portal/developer/` — a raw database viewer
  (literal `auth_user`/`accounts_profile` column values: username, email,
  password hash, role, raw contact info) in a wider layout than the rest
  of the site (better for dense tables — see FRONTEND.md's `wide`
  container variant). This exists specifically to demonstrate to faculty
  that the hashing/encryption requirements are actually in effect — once
  those are implemented for real, this page's output *is* the proof (hash
  strings and ciphertext instead of plaintext). Two menus from here:
  `/portal/admins/` (grant/revoke the Admin role — the only place that can
  happen) and `/portal/users/` (lock/suspend/ban Standard Users).

Regular users can report a post from its detail page; that both flags it
for the existing content-moderation view and creates a `Report` row admins
can act on.

## Databases: SQLite for development, Aiven MySQL for the demo

The project runs on **either** backend, selected by one line in your `.env`:

| `DB_ENGINE` | What it uses | When |
|---|---|---|
| `sqlite` *(default)* | a local `db.sqlite3` file | everyday development |
| `mysql` | the shared Aiven MySQL 8.4 server | the project demonstration, and any work that needs the shared data |

The application code and migrations are **identical** for both — switching is
never a code change. Check where you are with `python manage.py dbinfo`.

**Why SQLite for development:** no credentials, no network, no MySQL install,
and your experiments can't disturb anyone else. Start from nothing with:

```bash
python manage.py migrate
python manage.py seed_demo
```

**Step-by-step SQLite instructions live in `SQLITE_SETUP.txt`** — start there
if you're setting up a machine for the first time. There is nothing to install
for SQLite; it ships inside Python. `requirements-sqlite.txt` even lets you
skip `mysqlclient`, the one dependency that needs a compiler.

`seed_demo` creates the team's standard logins plus sample friends, posts,
messages and reports (see `SETUP.md` for the account table). It's idempotent,
and it refuses to run against the shared database unless you pass
`--allow-shared`.

**One thing to watch:** a migration you generate on SQLite still has to reach
MySQL. Commit the migration file; whoever is on `mysql` runs `migrate` there.
Before the demonstration, switch to `DB_ENGINE=mysql` and run `dbinfo` to
confirm the shared DB is reachable and fully migrated.

### The shared Aiven database

**Live and confirmed working:** a central MySQL 8.4 database hosted on Aiven
(free tier). This is what the demonstration runs against, and it's where
shared test data lives, so everyone sees the same state. All migrations are
already applied to it.

The real host/port/username/password are deliberately **not** written down
here or anywhere else in this repo (avoid publishing live infrastructure
endpoints, even to a private repo) — get them from a teammate directly
(chat/DM), and drop them into your own local `.env`, copied from
`.env.example`. `.env` is gitignored; it should be the only place these
values ever live on disk.

Aiven requires an encrypted connection - keep `MYSQL_SSL_MODE=REQUIRED` in
your `.env` for this database (no certificate file needed; verified working
with `mysqlclient`). Don't remove it.

If you're working offline or the shared DB is unreachable, use
`DB_ENGINE=sqlite` (above) — that's the simplest fallback. You can also point
`.env` at a local MySQL/MariaDB instance instead; only the `.env` values
change. If your local MySQL doesn't have SSL configured, set
`MYSQL_SSL_MODE=` (empty) too.

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
posts/         Photo feed: creation and encryption (posts are friends-only)
messaging/     Encrypted 1-on-1 direct messages (friends only)
social/        Likes, comments, and the friends system
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
