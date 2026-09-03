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

        try:
            connection.ensure_connection()
        except Exception as exc:
            self.stdout.write(self.style.ERROR(f"\nConnection: FAILED\n  {exc}"))
            return
        self.stdout.write(self.style.SUCCESS("\nConnection: OK"))

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
