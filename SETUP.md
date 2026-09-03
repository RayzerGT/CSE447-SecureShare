# Setup (do this once, on your own machine)

Full details/explanations live in `README.md` — this is just the checklist.

> **Setting up on SQLite for the first time?** `SQLITE_SETUP.txt` walks through
> the same thing step by step, with troubleshooting for each step. Use that if
> you'd prefer more hand-holding than this checklist gives.

1. **Clone the repo and open a terminal in it.**

2. **Python 3.13** (3.10+ probably works). Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   ```
   - Windows: `.venv\Scripts\activate`
   - macOS/Linux: `source .venv/bin/activate`

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   - macOS: if this fails on `mysqlclient`, run `brew install mysql-client pkg-config` first.
   - Linux: if this fails on `mysqlclient`, run `sudo apt install default-libmysqlclient-dev build-essential pkg-config` first.
   - Windows: should just work.

4. **Create your `.env` file:**
   ```bash
   cp .env.example .env   # Windows: copy .env.example .env
   ```
   Set `SECRET_KEY` — generate one with:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(50))"
   ```
   Leave `DB_ENGINE=sqlite` as-is. That's all you need for local development —
   no database credentials, no network.

5. **Create the database and load the team accounts:**
   ```bash
   python manage.py migrate
   python manage.py seed_demo
   ```
   `seed_demo` creates the standard logins plus sample friends, posts,
   messages and reports, so there's something to actually look at. It's safe
   to re-run, and it refuses to touch the shared database.

6. **Run the server:**
   ```bash
   python manage.py runserver
   ```

7. **Verify it works:** open `http://127.0.0.1:8000/accounts/login/` and log in
   as `alice` / `demo12345`. You should land on the feed with three posts.

   | Login page | Who | Password |
   |---|---|---|
   | `/accounts/login/` | `alice`, `bob`, `carol` | `demo12345` |
   | `/accounts/login/` | `Razeen`, `Afnan`, `Munia` (Developer) | `1234` |
   | `/accounts/login/` | `razeen_admin` (Admin) | `123` |

8. **Find your tasks:** open `todo.txt` and read your section. To find every
   spot in the code assigned to you:
   ```bash
   grep -rn "TODO(<your full name>)" .
   ```

## Switching to the shared Aiven database

You only need this for the **project demonstration**, or when you specifically
want to work against the shared data. Day-to-day, stay on SQLite.

1. Get the credentials from a teammate (chat/DM — they are deliberately not
   written down anywhere in this repo): host, port, database name, username,
   password.
2. In your `.env`, set:
   ```
   DB_ENGINE=mysql
   MYSQL_DATABASE=...
   MYSQL_USER=...
   MYSQL_PASSWORD=...
   MYSQL_HOST=...
   MYSQL_PORT=...
   MYSQL_SSL_MODE=REQUIRED
   ```
3. `python manage.py migrate` — usually reports "no migrations to apply",
   which is expected.

Switch back by setting `DB_ENGINE=sqlite` again. Your SQLite file is untouched
while you're on MySQL and vice versa, so you can flip between them freely.

**Restart `runserver` after editing `.env`.** Django's auto-reloader only
watches `.py` files, so a running server keeps using the old database until
you stop it (Ctrl+C) and start it again. If you switch backends and get
`no such table: django_session` or unexpected "no data", this is why.

**Careful:** on `mysql` you are writing to the database the whole team and the
demonstration share. Anything you delete, everyone loses.

## Which database am I on right now?

```bash
python manage.py dbinfo
```

Prints the active backend, whether it can connect, and whether any migrations
are unapplied. Worth running before the demo.

## If something breaks

- `python manage.py check` — catches most config/model mistakes.
- `python manage.py dbinfo` — confirms which database you're on and whether
  it's reachable.
- Changed `.env` and nothing happened? Restart `runserver` (see above).
- **Migrations you wrote work on SQLite but need to reach MySQL too.** Commit
  the migration files; whoever switches to `mysql` runs `migrate` there.
- Can't connect on `mysql` — check `MYSQL_SSL_MODE=REQUIRED` is set and the
  credentials have no typos (no quotes needed around values in `.env`).
- Want a clean slate on SQLite: delete `db.sqlite3`, then `migrate` and
  `seed_demo` again.
- Server won't start on port 8000 / old code seems to still be running —
  kill whatever's already using that port. Windows: `netstat -ano | findstr :8000`;
  macOS/Linux: `lsof -i :8000`.
