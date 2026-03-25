"""Tests for SQLAlchemy ORM models."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError as SAIntegrityError

from netwatchdog.database.connection import create_db_engine, create_session_factory
from netwatchdog.database.migrations import run_migrations
from netwatchdog.database.models import (
    ChangeEvent,
    Host,
    NotificationLog,
    PortHistory,
    PortState,
    ScanJob,
)


@pytest.fixture()
def session(tmp_path: Path):
    """Provide a session with all migrations applied."""
    engine = create_db_engine(tmp_path / "test.db")
    run_migrations(engine)
    factory = create_session_factory(engine)
    s = factory()
    yield s
    s.close()


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_host(session, ip: str = "192.168.1.1", label: str = "Router") -> Host:
    host = Host(ip_address=ip, label=label, created_at=_now(), updated_at=_now())
    session.add(host)
    session.flush()
    return host


def _make_scan_job(session, scan_type: str = "quick") -> ScanJob:
    job = ScanJob(
        scan_type=scan_type,
        status="completed",
        created_at=_now(),
    )
    session.add(job)
    session.flush()
    return job


def test_create_host(session):
    host = _make_host(session)
    session.commit()
    assert host.id is not None
    assert host.ip_address == "192.168.1.1"
    assert host.active == 1


def test_host_unique_ip(session):
    _make_host(session, ip="10.0.0.1")
    session.commit()
    with pytest.raises(SAIntegrityError):
        _make_host(session, ip="10.0.0.1")
        session.flush()
    session.rollback()


def test_create_scan_job(session):
    job = _make_scan_job(session)
    session.commit()
    assert job.id is not None
    assert job.scan_type == "quick"
    assert job.status == "completed"


def test_create_port_state(session):
    host = _make_host(session)
    job = _make_scan_job(session)
    ps = PortState(
        host_id=host.id, port=22, protocol="tcp", state="open",
        service_name="ssh", scan_job_id=job.id, last_seen_at=_now(),
    )
    session.add(ps)
    session.commit()
    assert ps.id is not None
    assert ps.host.ip_address == "192.168.1.1"
    assert ps.scan_job.scan_type == "quick"


def test_port_state_unique_constraint(session):
    host = _make_host(session)
    job = _make_scan_job(session)
    ps1 = PortState(
        host_id=host.id, port=80, protocol="tcp", state="open",
        scan_job_id=job.id, last_seen_at=_now(),
    )
    ps2 = PortState(
        host_id=host.id, port=80, protocol="tcp", state="closed",
        scan_job_id=job.id, last_seen_at=_now(),
    )
    session.add_all([ps1, ps2])
    with pytest.raises(Exception):
        session.commit()


def test_create_port_history(session):
    host = _make_host(session)
    job = _make_scan_job(session)
    ph = PortHistory(
        host_id=host.id, port=443, state="open",
        scan_job_id=job.id, observed_at=_now(),
    )
    session.add(ph)
    session.commit()
    assert ph.id is not None
    assert ph.host.ip_address == "192.168.1.1"


def test_create_change_event(session):
    host = _make_host(session)
    job = _make_scan_job(session)
    ce = ChangeEvent(
        host_id=host.id, port=22, protocol="tcp",
        previous_state=None, current_state="open",
        scan_job_id=job.id, detected_at=_now(),
    )
    session.add(ce)
    session.commit()
    assert ce.id is not None
    assert ce.notified == 0
    assert ce.previous_state is None
    assert ce.current_state == "open"


def test_create_notification_log(session):
    nl = NotificationLog(
        channel="email", change_event_ids="[1, 2]",
        status="sent", sent_at=_now(),
    )
    session.add(nl)
    session.commit()
    assert nl.id is not None


def test_host_cascade_deletes(session):
    host = _make_host(session)
    job = _make_scan_job(session)
    session.add(PortState(
        host_id=host.id, port=22, state="open",
        scan_job_id=job.id, last_seen_at=_now(),
    ))
    session.add(ChangeEvent(
        host_id=host.id, port=22, current_state="open",
        scan_job_id=job.id, detected_at=_now(),
    ))
    session.commit()

    session.delete(host)
    session.commit()

    assert session.query(PortState).count() == 0
    assert session.query(ChangeEvent).count() == 0


def test_host_relationships(session):
    host = _make_host(session)
    job = _make_scan_job(session)
    session.add(PortState(
        host_id=host.id, port=22, state="open",
        scan_job_id=job.id, last_seen_at=_now(),
    ))
    session.add(PortHistory(
        host_id=host.id, port=22, state="open",
        scan_job_id=job.id, observed_at=_now(),
    ))
    session.add(ChangeEvent(
        host_id=host.id, port=22, current_state="open",
        scan_job_id=job.id, detected_at=_now(),
    ))
    session.commit()

    assert len(host.port_states) == 1
    assert len(host.port_history) == 1
    assert len(host.change_events) == 1
