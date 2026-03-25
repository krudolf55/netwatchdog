"""Tests for database connection and migrations."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from sqlalchemy import inspect, text

from netwatchdog.database.connection import create_db_engine, create_session_factory
from netwatchdog.database.migrations import run_migrations


def test_engine_creates_file(tmp_path: Path):
    db_path = tmp_path / "sub" / "test.db"
    engine = create_db_engine(db_path)
    # Force a connection to create the file
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    assert db_path.exists()


def test_wal_mode_enabled(tmp_path: Path):
    db_path = tmp_path / "test.db"
    engine = create_db_engine(db_path, wal_mode=True)
    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA journal_mode"))
        mode = result.scalar()
        assert mode == "wal"


def test_foreign_keys_enabled(tmp_path: Path):
    db_path = tmp_path / "test.db"
    engine = create_db_engine(db_path)
    with engine.connect() as conn:
        result = conn.execute(text("PRAGMA foreign_keys"))
        assert result.scalar() == 1


def test_session_factory(tmp_path: Path):
    db_path = tmp_path / "test.db"
    engine = create_db_engine(db_path)
    factory = create_session_factory(engine)
    session = factory()
    result = session.execute(text("SELECT 1"))
    assert result.scalar() == 1
    session.close()


def test_run_migrations_creates_all_tables(tmp_path: Path):
    db_path = tmp_path / "test.db"
    engine = create_db_engine(db_path)
    applied = run_migrations(engine)
    assert 1 in applied

    table_names = inspect(engine).get_table_names()
    expected = {
        "schema_migrations", "hosts", "scan_jobs", "port_states",
        "port_history", "change_events", "notification_log",
    }
    assert expected.issubset(set(table_names))


def test_run_migrations_is_idempotent(tmp_path: Path):
    db_path = tmp_path / "test.db"
    engine = create_db_engine(db_path)
    first = run_migrations(engine)
    second = run_migrations(engine)
    assert len(first) >= 1
    assert len(second) == 0


def test_run_migrations_tracks_versions(tmp_path: Path):
    db_path = tmp_path / "test.db"
    engine = create_db_engine(db_path)
    run_migrations(engine)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version, description FROM schema_migrations")).fetchall()
    assert len(rows) >= 1
    versions = {r[0] for r in rows}
    assert 1 in versions  # initial schema always present


def test_run_migrations_applies_in_order(tmp_path: Path):
    """Create two migration files and verify they apply in order."""
    migrations_dir = tmp_path / "migrations"
    migrations_dir.mkdir()
    (migrations_dir / "0001_first.sql").write_text(
        "CREATE TABLE test_one (id INTEGER PRIMARY KEY);"
    )
    (migrations_dir / "0002_second.sql").write_text(
        "CREATE TABLE test_two (id INTEGER PRIMARY KEY);"
    )
    db_path = tmp_path / "test.db"
    engine = create_db_engine(db_path)
    applied = run_migrations(engine, migrations_dir=migrations_dir)
    assert applied == [1, 2]
    table_names = inspect(engine).get_table_names()
    assert "test_one" in table_names
    assert "test_two" in table_names
