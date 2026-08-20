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

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY", "insecure-dev-key-change-me")
DEBUG = os.getenv("DEBUG", "True") == "True"

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

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
    # authenticated request (accounts/security/session_manager.py).
    "accounts.security.session_manager.SecureSessionMiddleware",
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
            ],
        },
    },
]

WSGI_APPLICATION = "secureshare.wsgi.application"
ASGI_APPLICATION = "secureshare.asgi.application"

# ---------------------------------------------------------------------------
# Database (MySQL, per project requirements)
#
# Points at the team's shared central database (Aiven, by default) so
# everyone works against the same data/migration state. Aiven requires TLS,
# hence MYSQL_SSL_MODE=REQUIRED by default - if you point this at a local
# MySQL/MariaDB that doesn't have SSL set up, set MYSQL_SSL_MODE= (empty) in
# your own .env to disable it.
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Password hashing
#
# NOTE: The project requires passwords to be hashed AND salted using a
# from-scratch implementation (no framework-provided hashers). Django's
# default PASSWORD_HASHERS use PBKDF2/bcrypt/argon2 out of the box, which
# would violate that requirement, so the default is intentionally left as
# a placeholder here.
#
# TODO(Afnan Satter): implement a custom hasher in
# accounts/security/hashing.py and register it below, e.g.:
#   PASSWORD_HASHERS = ["accounts.security.hashing.FromScratchPasswordHasher"]
# ---------------------------------------------------------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # placeholder only - replace per above
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
# TODO(Razeen Hassan): still riding on Django's default signed session cookie
# rather than a custom/from-scratch token scheme - see session_manager.py.
# ---------------------------------------------------------------------------
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
