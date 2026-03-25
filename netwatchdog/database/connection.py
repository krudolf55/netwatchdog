"""SQLite database connection management."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import event, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def _set_sqlite_pragmas(dbapi_conn, connection_record):  # type: ignore[no-untyped-def]
    """Enable WAL mode and foreign keys on every new connection."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_db_engine(db_path: Path, wal_mode: bool = True) -> Engine:
    """Create a SQLAlchemy engine for the given SQLite database path.

    Creates parent directories if they don't exist.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    if wal_mode:
        event.listen(engine, "connect", _set_sqlite_pragmas)
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to the given engine."""
    return sessionmaker(bind=engine)
