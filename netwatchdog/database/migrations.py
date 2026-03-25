"""Simple SQL-file-based migration runner.

Migration files live in the migrations/ directory and are named like:
    0001_initial_schema.sql
    0002_add_scan_metadata.sql

Each migration runs inside a transaction. Applied versions are tracked in
the schema_migrations table.
"""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.engine import Engine

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "migrations"

_BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    description TEXT,
    applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
"""

_MIGRATION_FILE_PATTERN = re.compile(r"^(\d{4})_(.+)\.sql$")


def _get_migration_files(migrations_dir: Path) -> list[tuple[int, str, Path]]:
    """Return sorted list of (version, description, path) from the migrations dir."""
    migrations: list[tuple[int, str, Path]] = []
    if not migrations_dir.exists():
        return migrations
    for f in sorted(migrations_dir.iterdir()):
        match = _MIGRATION_FILE_PATTERN.match(f.name)
        if match:
            version = int(match.group(1))
            description = match.group(2).replace("_", " ")
            migrations.append((version, description, f))
    return migrations


def _get_applied_versions(engine: Engine) -> set[int]:
    """Return the set of already-applied migration versions."""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version FROM schema_migrations"))
        return {row[0] for row in rows}


def run_migrations(engine: Engine, migrations_dir: Path | None = None) -> list[int]:
    """Apply any pending SQL migrations and return list of newly applied versions.

    Idempotent — skips migrations that have already been applied.
    """
    if migrations_dir is None:
        migrations_dir = MIGRATIONS_DIR

    # Bootstrap the tracking table
    with engine.begin() as conn:
        conn.execute(text(_BOOTSTRAP_SQL))

    applied = _get_applied_versions(engine)
    migration_files = _get_migration_files(migrations_dir)
    newly_applied: list[int] = []

    for version, description, path in migration_files:
        if version in applied:
            continue
        sql = path.read_text()
        with engine.begin() as conn:
            # Split on semicolons to handle multi-statement files
            for statement in sql.split(";"):
                statement = statement.strip()
                if statement:
                    conn.execute(text(statement))
            conn.execute(
                text(
                    "INSERT INTO schema_migrations (version, description) "
                    "VALUES (:version, :description)"
                ),
                {"version": version, "description": description},
            )
        newly_applied.append(version)

    return newly_applied
