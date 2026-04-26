"""Tests for config-to-database host syncing."""

from __future__ import annotations

from pathlib import Path

from periscan.config import Config
from periscan.database.connection import create_db_engine, create_session_factory
from periscan.database.migrations import run_migrations
from periscan.database.models import Host
from periscan.database.sync import sync_hosts_from_config


def _setup(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    run_migrations(engine)
    factory = create_session_factory(engine)
    return engine, factory()


def test_sync_adds_new_hosts(tmp_path: Path):
    _, session = _setup(tmp_path)
    cfg = Config.model_validate({
        "hosts": {"addresses": ["10.0.0.1", "10.0.0.2"]},
    })
    counts = sync_hosts_from_config(session, cfg)
    assert counts["added"] == 2
    assert session.query(Host).count() == 2
    host = session.query(Host).filter_by(ip_address="10.0.0.1").one()
    assert host.source == "config"


def test_sync_applies_labels(tmp_path: Path):
    _, session = _setup(tmp_path)
    cfg = Config.model_validate({
        "hosts": {
            "addresses": ["10.0.0.1"],
            "labels": {"10.0.0.1": "Router"},
        },
    })
    sync_hosts_from_config(session, cfg)
    host = session.query(Host).filter_by(ip_address="10.0.0.1").one()
    assert host.label == "Router"


def test_sync_idempotent(tmp_path: Path):
    _, session = _setup(tmp_path)
    cfg = Config.model_validate({"hosts": {"addresses": ["10.0.0.1"]}})
    sync_hosts_from_config(session, cfg)
    counts = sync_hosts_from_config(session, cfg)
    assert counts["added"] == 0
    assert counts["unchanged"] == 1
    assert session.query(Host).count() == 1


def test_sync_promotes_cli_host_to_config(tmp_path: Path):
    _, session = _setup(tmp_path)
    # Add a CLI host first
    from datetime import datetime
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    host = Host(ip_address="10.0.0.1", source="cli", created_at=now, updated_at=now)
    session.add(host)
    session.commit()

    # Now sync config that includes the same IP
    cfg = Config.model_validate({"hosts": {"addresses": ["10.0.0.1"]}})
    counts = sync_hosts_from_config(session, cfg)
    assert counts["updated"] == 1
    host = session.query(Host).filter_by(ip_address="10.0.0.1").one()
    assert host.source == "config"


def test_sync_expands_cidr(tmp_path: Path):
    _, session = _setup(tmp_path)
    cfg = Config.model_validate({"hosts": {"addresses": ["10.0.0.0/30"]}})
    counts = sync_hosts_from_config(session, cfg)
    assert counts["added"] == 2  # .1 and .2
    ips = {h.ip_address for h in session.query(Host).all()}
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips


def test_sync_reactivates_inactive_host(tmp_path: Path):
    _, session = _setup(tmp_path)
    from datetime import datetime
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    host = Host(ip_address="10.0.0.1", source="config", active=0, created_at=now, updated_at=now)
    session.add(host)
    session.commit()

    cfg = Config.model_validate({"hosts": {"addresses": ["10.0.0.1"]}})
    counts = sync_hosts_from_config(session, cfg)
    assert counts["updated"] == 1
    host = session.query(Host).filter_by(ip_address="10.0.0.1").one()
    assert host.active == 1
