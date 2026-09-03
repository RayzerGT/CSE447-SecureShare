"""
Django settings for the SecureShare project (BRACU_flex, Group 05, CSE447).

Full skeleton: all 6 apps are active. See todo.txt in the project root for
exactly who owns which file/function - task ownership does not follow app
boundaries exactly (e.g. accounts/ is split between Razeen Hassan and
Mos. Mahabuba Akter Munia; posts/ is split between Afnan Satter and Munia).

NOTE: The actual cryptographic requirements (custom RSA/ECC, hashing+salting,
2FA, RBAC decision logic, secure session tokens, MAC) are NOT implemented
here - see the TODO-marked stub modules throughout, and todo.txt for who's
building what.
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY", "insecure-dev-key-change-me")
DEBUG = os.getenv("DEBUG", "True") == "True"

# Root secret for crypto_core's Key Management Module - wraps/unwraps every
# user's stored private key. See crypto_core/key_management/master_key.py
# for the "e:d:n" format and how to generate a stable one. Left unset here
# (like SECRET_KEY's insecure-dev fallback), an ephemeral one is generated
# in memory per process if this is empty.
KMM_MASTER_KEY = os.getenv("KMM_MASTER_KEY", "")

# "Sign in with Google" - see accounts/security/google_oauth.py. All three
# blank (the default if unset) hides the button on the login page entirely,
# so this is safe to leave empty on a machine with no Google credentials set up.
GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
GOOGLE_OAUTH_REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI", "")

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

# Surfaces the dev-only OTP that accounts/security/two_factor.py logs when
# DEBUG is on, so a 2FA code is visible in the runserver console.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {
        "accounts.security.two_factor": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # SecureShare apps - see todo.txt for per-file ownership within each
    "accounts",
    "crypto_core",
    "posts",
    "messaging",
    "social",
    "moderation",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",

    # Enforces the SESSION_TIMEOUT_MINUTES absolute session expiry on every
    # authenticated request (accounts/security/session_manager.py). Must run
    # BEFORE RoleAccessMiddleware below, so an expired session is logged out
    # (request.user -> AnonymousUser) before role-based redirect logic sees it.
    "accounts.security.session_manager.SecureSessionMiddleware",

    # Confines Admin/Developer accounts to their own panel only - no feed/
    # upload/messaging/social for them (moderation/permissions.py).
    "moderation.permissions.RoleAccessMiddleware",
]

ROOT_URLCONF = "secureshare.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                # Feeds `pending_request_count` to the Friends nav badge.
                "social.context_processors.pending_requests",
            ],
        },
    },
]

WSGI_APPLICATION = "secureshare.wsgi.application"
ASGI_APPLICATION = "secureshare.asgi.application"

# ---------------------------------------------------------------------------
# Database - two interchangeable backends, chosen by DB_ENGINE in your .env
#
#   DB_ENGINE=sqlite  (default)  -> a local db.sqlite3 file. Zero setup, no
#                                   credentials, no network. Use this for
#                                   day-to-day development.
#   DB_ENGINE=mysql              -> the team's shared central database on
#                                   Aiven. Use this for the project
#                                   demonstration, and any time you need to
#                                   work against the shared data.
#
# Both backends run the exact same migrations and the same application code -
# switching is only ever a one-line change in .env, never a code change.
#
# Aiven requires TLS, hence MYSQL_SSL_MODE=REQUIRED by default. If you point
# the mysql backend at a local MySQL/MariaDB without SSL, set MYSQL_SSL_MODE=
# (empty) in your own .env.
#
# Run `python manage.py dbinfo` to see which backend you are currently on.
# ---------------------------------------------------------------------------
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").strip().lower()

if DB_ENGINE == "mysql":
    _MYSQL_OPTIONS = {
        "charset": "utf8mb4",
        "init_command": "SET sql_mode='STRICT_TRANS_TABLES'",
    }
    _MYSQL_SSL_MODE = os.getenv("MYSQL_SSL_MODE", "REQUIRED")
    if _MYSQL_SSL_MODE:
        _MYSQL_OPTIONS["ssl_mode"] = _MYSQL_SSL_MODE

    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "NAME": os.getenv("MYSQL_DATABASE", "secureshare"),
            "USER": os.getenv("MYSQL_USER", "secureshare_user"),
            "PASSWORD": os.getenv("MYSQL_PASSWORD", ""),
            "HOST": os.getenv("MYSQL_HOST", "127.0.0.1"),
            "PORT": os.getenv("MYSQL_PORT", "3306"),
            "OPTIONS": _MYSQL_OPTIONS,
        }
    }
elif DB_ENGINE == "sqlite":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / os.getenv("SQLITE_NAME", "db.sqlite3"),
            # Fail fast instead of hanging when another process (e.g. a stray
            # runserver) holds a write lock on the file.
            "OPTIONS": {"timeout": 20},
        }
    }
else:
    raise ImproperlyConfigured(
        f"DB_ENGINE must be 'sqlite' or 'mysql', got {DB_ENGINE!r}. "
        "Check the DB_ENGINE line in your .env file."
    )

# ---------------------------------------------------------------------------
# Password hashing
#
# The project requires passwords to be hashed AND salted using a from-scratch
# implementation (no framework-provided hashers). FromScratchPasswordHasher
# (accounts/security/hashing.py) implements SHA-256 and an iterated-hash
# key-stretching scheme by hand and is the sole entry below, so
# User.set_password()/authenticate()/check_password() all go through it.
#
# CAVEAT: this does not retroactively rehash passwords already stored under
# Django's old default hasher - pre-existing accounts (e.g. on the shared
# Aiven DB) need to re-register or have their password reset.
# ---------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "accounts.security.hashing.FromScratchPasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Dhaka"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "posts:feed"
LOGOUT_REDIRECT_URL = "accounts:login"

# ---------------------------------------------------------------------------
# Session / cookie security
#
# Two separate things, deliberately decoupled:
#   - SESSION_COOKIE_AGE: how long the underlying Django session
#     cookie/session-store is allowed to live at all. Kept generous (1 day)
#     so it never preempts the check below.
#   - SESSION_TIMEOUT_MINUTES / APP_SESSION_TIMEOUT_SECONDS: the actual
#     enforced "log out after this long" policy, applied by our own code
#     (accounts.models.ActiveSession + accounts.security.session_manager.
#     SecureSessionMiddleware), not by Django's framework default. This is
#     what "session ends N minutes after login" means here. Override via the
#     SESSION_TIMEOUT_MINUTES env var.
#
# Sessions are additionally pinned to the browser and IP that created them
# (accounts/security/session_manager.py, rule 2 - anti-hijacking). IP pinning
# is the part most likely to cause a false logout on a flaky mobile network,
# so it can be turned off on its own without giving up browser pinning.
# ---------------------------------------------------------------------------
SESSION_BIND_IP = os.getenv("SESSION_BIND_IP", "True") == "True"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False") == "True"
SESSION_COOKIE_AGE = 60 * 60 * 24  # 1 day - just a ceiling, not the enforced policy (see above)
SESSION_SAVE_EVERY_REQUEST = False  # keep expiry absolute (from login), not sliding/idle-based
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"

SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "5"))
APP_SESSION_TIMEOUT_SECONDS = SESSION_TIMEOUT_MINUTES * 60
