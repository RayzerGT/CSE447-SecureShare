# SecureShare

A security-first, friends-only photo sharing web application, similar in
layout to Instagram. Users create a profile, send and accept friend
requests, upload photos with captions, like and comment on posts, and
exchange direct messages. Visibility is strictly friend-based — you only
ever see posts belonging to you or to an accepted friend. There is no
public feed.

The point of the project is what happens underneath. Every sensitive value
is encrypted or hashed before it reaches the database, and all of the
cryptography is written from scratch rather than imported:

- **RSA** (1024-bit, PKCS#1 v1.5) — profile contact details, post captions,
  post images, avatars, and the wrapping of every stored private key.
- **ECC** (secp256k1, EC-ElGamal) — direct messages.
- **SHA-256** — password hashing, with a unique 16-byte salt per user.
- **HMAC-SHA256** — integrity tags on every encrypted record, and the
  TOTP codes used for two-factor authentication.

No cryptographic library is used anywhere in the security path; `hashlib`,
`hmac`, `cryptography` and `pycryptodome` appear nowhere in the project.

The application also implements a Key Management Module with key rotation,
role-based access control across three roles, moderation tooling, an audit
log, and session management with absolute timeouts and device binding.

Uploaded images are never stored as files. They are encrypted and kept as
blobs in the database, and served only through endpoints that check who is
asking.

---

## Running it locally

Roughly five minutes. The default setup uses SQLite, so there is no
database server to install and no credentials to configure.

### 1. Check your Python version

```bash
python --version
```

Python 3.10 or newer. The project was built on 3.13.3. If `python` is not
found, try `python3` and use that everywhere below.

### 2. Get the code

```bash
git clone https://github.com/RayzerGT/CSE447-SecureShare.git
cd CSE447-SecureShare
```

### 3. Create and activate a virtual environment

```bash
python -m venv .venv
```

Then activate it:

| Platform | Command |
|---|---|
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |
| Windows (cmd) | `.venv\Scripts\activate.bat` |
| macOS / Linux | `source .venv/bin/activate` |

Your prompt should now start with `(.venv)`. You need to do this every time
you open a new terminal for this project — if a later command reports "no
module named django", this is almost always why.

### 4. Install the dependencies

```bash
pip install -r requirements-sqlite.txt
```

This is the normal `requirements.txt` minus `mysqlclient`, the one package
that needs a C compiler and the MySQL client libraries. You do not need it
while you are on SQLite.

### 5. Create your `.env` file

```bash
cp .env.example .env        # Windows: copy .env.example .env
```

Open `.env` and set two values.

**`SECRET_KEY`** — any long random string:

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

**`KMM_MASTER_KEY`** — the root of trust for the Key Management Module.
Every private key and every integrity tag is derived from it, so if you
leave it blank the app generates a throwaway key at startup and your
encrypted data stops decrypting the moment you restart the server:

```bash
python -c "from crypto_core.key_management.master_key import generate_master_key_env_line; print(generate_master_key_env_line())"
```

That prints a complete `KMM_MASTER_KEY=...` line — paste it in, replacing
the empty one.

Leave `DB_ENGINE=sqlite` as it is. You can ignore every `MYSQL_*` line;
they are only read when `DB_ENGINE=mysql`.

`.env` is gitignored and never gets committed.

### 6. Create the database

```bash
python manage.py migrate
```

This creates `db.sqlite3` in the project folder and builds every table.
That file is gitignored, so your local data is yours alone.

### 7. Load the sample data

```bash
python manage.py seed_demo
```

A fresh database has no users at all, so without this you cannot log in to
anything. This creates one account for each of the three roles plus sample
friends, posts, likes, comments, messages and reports, and **prints the
usernames and passwords it created** when it finishes. It is safe to run
again — it tops up what is missing instead of creating duplicates.

### 8. Run the server

```bash
python manage.py runserver
```

Open **http://127.0.0.1:8000/accounts/login/** and sign in with one of the
accounts `seed_demo` printed. Stop the server with `Ctrl+C`.

Use `127.0.0.1` rather than `localhost`. They are different origins as far
as the browser is concerned, and the Google sign-in redirect is registered
against `127.0.0.1`.

---

## Optional extras

**Google sign-in.** The "Sign in with Google" button only appears once
`GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` and
`GOOGLE_OAUTH_REDIRECT_URI` are set in `.env`. Create the credentials in
the Google Cloud Console under *APIs & Services → Credentials → OAuth
client ID → Web application*, and register
`http://127.0.0.1:8000/accounts/google/callback/` as an authorised redirect
URI. Without these the button stays hidden and password login works
normally.

**Two-factor authentication.** Standard Users can enable TOTP from the
Security page. Because the codes are built on SHA-256 rather than SHA-1,
you need an authenticator that honours the algorithm parameter — Aegis,
FreeOTP, Bitwarden or 1Password. Google Authenticator always assumes SHA-1
and its codes will not match.

**Using MySQL instead.** Set `DB_ENGINE=mysql` in `.env`, fill in the
`MYSQL_*` values, and install the full `requirements.txt` (which includes
`mysqlclient`). The application code and migrations are identical for both
backends; switching is never a code change.

---

## Useful commands

| Command | What it does |
|---|---|
| `python manage.py dbinfo` | Shows which database backend is active and whether migrations are up to date |
| `python manage.py seed_demo` | Creates the demo accounts and sample content |
| `python manage.py check` | Catches configuration and model errors |
| `python manage.py secure_media` | Encrypts any plaintext image left in `media/`, then deletes the plaintext file |
| `python manage.py backfill_post_thumbnails` | Re-encodes older posts so they have an encrypted thumbnail |

The last two only matter when upgrading a database that predates image
encryption. A fresh install created with `migrate` and `seed_demo` never
needs them.

---

## Project layout

```
secureshare/   Django settings, URLs, middleware chain
crypto_core/   All from-scratch cryptography
  asymmetric/    rsa_scratch.py, ecc_scratch.py
  mac/           hmac_scratch.py
  key_management/  kmm.py, master_key.py
  media_vault.py, encryption_service.py
accounts/      Registration, login, 2FA, profile, sessions
  security/      hashing.py, two_factor.py, session_manager.py
posts/         Upload, feed, encryption, image serving
messaging/     Encrypted direct messages
social/        Friends, likes, comments, search
moderation/    Reports, admin panel, developer portal, audit log
templates/     Shared base template and partials
static/        CSS and JavaScript
```

---

## Troubleshooting

**"No module named django"** — the virtual environment is not active. See
step 3.

**Encrypted data suddenly will not decrypt after a restart** —
`KMM_MASTER_KEY` is empty in your `.env`. See step 5. If it was empty while
you created data, that data cannot be recovered; delete `db.sqlite3` and
re-run steps 6 and 7.

**Code changes do not take effect** — an old server process may still be
bound to port 8000. Find it with `netstat -ano | findstr :8000` on Windows,
or `lsof -i :8000` on macOS and Linux, and stop it.

**Google sign-in reports "invalid or expired request"** — you opened the
site on `localhost` instead of `127.0.0.1`. See step 8.
