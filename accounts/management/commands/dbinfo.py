"""
accounts/management/commands/dbinfo.py
Shared tooling (lives under accounts/ because Django discovers management
commands from installed apps; it is not account-specific).

    python manage.py dbinfo

Prints which database backend this checkout is currently pointed at, whether
it can actually connect, and whether any migrations are unapplied. The
project can run on either a local SQLite file or the shared Aiven MySQL
server (see DB_ENGINE in settings.py), so "which database am I on right
now?" is a question worth being able to answer in one command - especially
before the demonstration.
"""

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection
from django.db.migrations.executor import MigrationExecutor


class Command(BaseCommand):
    help = "Show which database backend is active, and whether migrations are up to date."

    def handle(self, *args, **options):
        config = settings.DATABASES["default"]
        engine = config["ENGINE"].rsplit(".", 1)[-1]

        if engine == "sqlite3":
            self.stdout.write(self.style.MIGRATE_HEADING("Backend: SQLite (local file)"))
            path = config["NAME"]
            self.stdout.write(f"  File:     {path}")
            self.stdout.write(f"  Exists:   {'yes' if getattr(path, 'exists', lambda: False)() else 'no (run migrate)'}")
            self.stdout.write("  Scope:    local to your machine - nobody else sees your data")
        else:
            self.stdout.write(self.style.MIGRATE_HEADING("Backend: MySQL (shared team server)"))
            self.stdout.write(f"  Host:     {config['HOST']}:{config['PORT']}")
            self.stdout.write(f"  Database: {config['NAME']}")
            self.stdout.write(f"  User:     {config['USER']}")
            self.stdout.write(self.style.WARNING("  Scope:    SHARED - your changes affect the whole team"))

        # Connectivity
        try:
            connection.ensure_connection()
        except Exception as exc:  # noqa: BLE001 - we want to report any driver/network error verbatim
            self.stdout.write(self.style.ERROR(f"\nConnection: FAILED\n  {exc}"))
            return
        self.stdout.write(self.style.SUCCESS("\nConnection: OK"))

        # Unapplied migrations
        executor = MigrationExecutor(connection)
        targets = executor.loader.graph.leaf_nodes()
        plan = executor.migration_plan(targets)
        if plan:
            self.stdout.write(self.style.WARNING(f"Migrations: {len(plan)} unapplied - run `python manage.py migrate`"))
            for migration, _backwards in plan:
                self.stdout.write(f"  - {migration.app_label}.{migration.name}")
        else:
            self.stdout.write(self.style.SUCCESS("Migrations: up to date"))

        self.stdout.write("\nSwitch backends by editing DB_ENGINE in your .env (sqlite | mysql).")
