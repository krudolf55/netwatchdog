"""Tests for the change detection algorithm."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from periscan.database.connection import create_db_engine, create_session_factory
from periscan.database.migrations import run_migrations
from periscan.database.models import (
    ChangeEvent,
    Host,
    PortHistory,
    PortState,
    ScanJob,
)
from periscan.detector.change_detector import ChangeDetector, _parse_port_range
from periscan.scanner.base import (
    HostResult,
    PortResult,
    PortState as PortStateEnum,
    ScanResult,
)


def _now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture()
def session(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    run_migrations(engine)
    factory = create_session_factory(engine)
    s = factory()
    yield s
    s.close()


@pytest.fixture()
def host(session):
    h = Host(ip_address="10.0.0.1", source="cli", created_at=_now(), updated_at=_now())
    session.add(h)
    session.flush()
    return h


@pytest.fixture()
def scan_job(session):
    job = ScanJob(scan_type="quick", status="running", created_at=_now())
    session.add(job)
    session.flush()
    return job


# ---------------------------------------------------------------------------
# Port range parser
# ---------------------------------------------------------------------------


class TestParsePortRange:
    def test_range(self):
        assert _parse_port_range("1-5") == {1, 2, 3, 4, 5}

    def test_single(self):
        assert _parse_port_range("22") == {22}

    def test_comma_list(self):
        assert _parse_port_range("22,80,443") == {22, 80, 443}

    def test_mixed(self):
        assert _parse_port_range("22,80-82,443") == {22, 80, 81, 82, 443}


# ---------------------------------------------------------------------------
# First scan — everything is new
# ---------------------------------------------------------------------------


def test_first_scan_detects_new_open_ports(session, host, scan_job):
    """First scan: open ports should create change events."""
    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(
            ip_address="10.0.0.1",
            ports=[
                PortResult(port=22, protocol="tcp", state=PortStateEnum.OPEN, service_name="ssh"),
                PortResult(port=80, protocol="tcp", state=PortStateEnum.OPEN, service_name="http"),
            ],
        )],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, scan_job)

    assert len(changes) == 2
    assert changes[0].port == 22
    assert changes[0].previous_state is None
    assert changes[0].current_state == "open"
    assert changes[1].port == 80

    # port_states should be created
    states = session.query(PortState).filter_by(host_id=host.id).all()
    assert len(states) == 2

    # port_history should be recorded
    history = session.query(PortHistory).filter_by(host_id=host.id).all()
    assert len(history) == 2


def test_first_scan_closed_ports_not_recorded_as_change(session, host, scan_job):
    """First scan: closed ports are stored but not flagged as changes."""
    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(
            ip_address="10.0.0.1",
            ports=[
                PortResult(port=22, protocol="tcp", state=PortStateEnum.CLOSED),
            ],
        )],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, scan_job)
    assert len(changes) == 0

    # port_state is still stored
    states = session.query(PortState).filter_by(host_id=host.id).all()
    assert len(states) == 1
    assert states[0].state == "closed"


# ---------------------------------------------------------------------------
# State transitions
# ---------------------------------------------------------------------------


def test_port_opened(session, host, scan_job):
    """Port was closed, now open — should detect change."""
    # Seed existing state
    session.add(PortState(
        host_id=host.id, port=22, protocol="tcp", state="closed",
        scan_job_id=scan_job.id, last_seen_at=_now(),
    ))
    session.flush()

    # New scan job
    job2 = ScanJob(scan_type="quick", status="running", created_at=_now())
    session.add(job2)
    session.flush()

    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(
            ip_address="10.0.0.1",
            ports=[PortResult(port=22, protocol="tcp", state=PortStateEnum.OPEN, service_name="ssh")],
        )],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, job2)
    assert len(changes) == 1
    assert changes[0].previous_state == "closed"
    assert changes[0].current_state == "open"
    assert changes[0].current_service == "ssh"


def test_port_closed(session, host, scan_job):
    """Port was open, now absent from scan within range — should mark as closed."""
    session.add(PortState(
        host_id=host.id, port=22, protocol="tcp", state="open",
        service_name="ssh", scan_job_id=scan_job.id, last_seen_at=_now(),
    ))
    session.flush()

    job2 = ScanJob(scan_type="quick", status="running", created_at=_now())
    session.add(job2)
    session.flush()

    detector = ChangeDetector(session)
    # Scan returns no ports for this host
    scan_result = ScanResult(
        hosts=[HostResult(ip_address="10.0.0.1", ports=[])],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, job2)
    assert len(changes) == 1
    assert changes[0].previous_state == "open"
    assert changes[0].current_state == "closed"

    # port_state should be updated
    ps = session.query(PortState).filter_by(host_id=host.id, port=22).one()
    assert ps.state == "closed"


def test_port_filtered(session, host, scan_job):
    """Port goes from open to filtered — should detect change."""
    session.add(PortState(
        host_id=host.id, port=80, protocol="tcp", state="open",
        scan_job_id=scan_job.id, last_seen_at=_now(),
    ))
    session.flush()

    job2 = ScanJob(scan_type="quick", status="running", created_at=_now())
    session.add(job2)
    session.flush()

    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(
            ip_address="10.0.0.1",
            ports=[PortResult(port=80, protocol="tcp", state=PortStateEnum.FILTERED)],
        )],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, job2)
    assert len(changes) == 1
    assert changes[0].previous_state == "open"
    assert changes[0].current_state == "filtered"


def test_no_change_when_state_same(session, host, scan_job):
    """Port stays open — no change event should be created."""
    session.add(PortState(
        host_id=host.id, port=22, protocol="tcp", state="open",
        service_name="ssh", scan_job_id=scan_job.id, last_seen_at=_now(),
    ))
    session.flush()

    job2 = ScanJob(scan_type="quick", status="running", created_at=_now())
    session.add(job2)
    session.flush()

    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(
            ip_address="10.0.0.1",
            ports=[PortResult(port=22, protocol="tcp", state=PortStateEnum.OPEN, service_name="ssh")],
        )],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, job2)
    assert len(changes) == 0

    # last_seen_at should be updated (heartbeat)
    ps = session.query(PortState).filter_by(host_id=host.id, port=22).one()
    assert ps.scan_job_id == job2.id


# ---------------------------------------------------------------------------
# Port range boundary handling
# ---------------------------------------------------------------------------


def test_port_outside_quick_scan_range_not_closed(session, host, scan_job):
    """Port 8080 was found in a prior full scan. Quick scan (1-1024) should NOT close it."""
    session.add(PortState(
        host_id=host.id, port=8080, protocol="tcp", state="open",
        scan_job_id=scan_job.id, last_seen_at=_now(),
    ))
    session.flush()

    job2 = ScanJob(scan_type="quick", status="running", created_at=_now())
    session.add(job2)
    session.flush()

    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(ip_address="10.0.0.1", ports=[])],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, job2)
    assert len(changes) == 0  # Port 8080 is outside 1-1024, not marked closed

    ps = session.query(PortState).filter_by(host_id=host.id, port=8080).one()
    assert ps.state == "open"  # Still open


def test_port_inside_full_scan_range_is_closed(session, host, scan_job):
    """Full scan (1-65535) should close port 8080 if it's absent."""
    session.add(PortState(
        host_id=host.id, port=8080, protocol="tcp", state="open",
        scan_job_id=scan_job.id, last_seen_at=_now(),
    ))
    session.flush()

    job2 = ScanJob(scan_type="full", status="running", created_at=_now())
    session.add(job2)
    session.flush()

    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(ip_address="10.0.0.1", ports=[])],
        scan_type="full",
        port_range="1-65535",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, job2)
    assert len(changes) == 1
    assert changes[0].port == 8080
    assert changes[0].current_state == "closed"


# ---------------------------------------------------------------------------
# Multiple hosts
# ---------------------------------------------------------------------------


def test_multiple_hosts(session, scan_job):
    """Detect changes across multiple hosts in one scan."""
    h1 = Host(ip_address="10.0.0.1", source="cli", created_at=_now(), updated_at=_now())
    h2 = Host(ip_address="10.0.0.2", source="cli", created_at=_now(), updated_at=_now())
    session.add_all([h1, h2])
    session.flush()

    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[
            HostResult(
                ip_address="10.0.0.1",
                ports=[PortResult(port=22, protocol="tcp", state=PortStateEnum.OPEN)],
            ),
            HostResult(
                ip_address="10.0.0.2",
                ports=[PortResult(port=80, protocol="tcp", state=PortStateEnum.OPEN)],
            ),
        ],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, scan_job)
    assert len(changes) == 2
    change_ports = {(c.host_id, c.port) for c in changes}
    assert (h1.id, 22) in change_ports
    assert (h2.id, 80) in change_ports


# ---------------------------------------------------------------------------
# Unknown host
# ---------------------------------------------------------------------------


def test_unknown_host_skipped(session, scan_job):
    """Results for IPs not in the DB should be skipped, not crash."""
    detector = ChangeDetector(session)
    scan_result = ScanResult(
        hosts=[HostResult(
            ip_address="192.168.99.99",
            ports=[PortResult(port=22, protocol="tcp", state=PortStateEnum.OPEN)],
        )],
        scan_type="quick",
        port_range="1-1024",
        scanner_tool="nmap",
    )

    changes = detector.process(scan_result, scan_job)
    assert len(changes) == 0
