# Setup (do this once, on your own machine)

Full details/explanations live in `README.md` — this is just the checklist.

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

4. **Get the shared database credentials from a teammate** (chat/DM — they are
   deliberately not written down anywhere in this repo). You need: host,
   port, database name, username, password.

5. **Create your `.env` file:**
   ```bash
   cp .env.example .env   # Windows: copy .env.example .env
   ```
   Open `.env` and fill in:
   - `SECRET_KEY` — generate one: `python -c "import secrets; print(secrets.token_urlsafe(50))"`
   - `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_HOST`, `MYSQL_PORT` — from step 4
   - `MYSQL_SSL_MODE=REQUIRED` — leave this as-is (the shared DB requires an encrypted connection)

6. **Apply migrations** (should report "no migrations to apply" if the shared
   DB is already up to date — that's expected, not an error):
   ```bash
   python manage.py migrate
   ```

7. **Run the server:**
   ```bash
   python manage.py runserver
   ```

8. **Verify it works:** open `http://127.0.0.1:8000/accounts/register/`,
   create an account, then log in at `http://127.0.0.1:8000/accounts/login/`.
   You should land on the feed page.

9. **Find your tasks:** open `todo.txt` and read your section. To find every
   spot in the code assigned to you:
   ```bash
   grep -rn "TODO(<your full name>)" .
   ```

## If something breaks

- `python manage.py check` — catches most config/model mistakes.
- Can't connect to the database — double check `MYSQL_SSL_MODE=REQUIRED` is
  set and the credentials from step 4 don't have typos (no quotes needed
  around values in `.env`).
- Server won't start on port 8000 / old code seems to still be running —
  kill whatever's already using that port. Windows: `netstat -ano | findstr :8000`;
  macOS/Linux: `lsof -i :8000`.
