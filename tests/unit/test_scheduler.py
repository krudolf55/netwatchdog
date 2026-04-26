"""Tests for scheduler jobs, manager, and CLI integration."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from textwrap import dedent
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from periscan.config import Config
from periscan.database.connection import create_db_engine, create_session_factory
from periscan.database.migrations import run_migrations
from periscan.database.models import ChangeEvent, Host, PortState, ScanJob
from periscan.database.sync import sync_hosts_from_config
from periscan.notifier.base import BaseNotifier
from periscan.scanner.base import HostResult, PortResult, PortState as PSEnum, ScanResult
from periscan.scheduler.jobs import run_scan_job
from periscan.scheduler.manager import _parse_cron


def _now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Cron parser
# ---------------------------------------------------------------------------


class TestParseCron:
    def test_valid_daily(self):
        trigger = _parse_cron("0 2 * * *")
        assert trigger is not None

    def test_valid_weekly(self):
        trigger = _parse_cron("0 3 * * 0")
        assert trigger is not None

    def test_invalid_fields(self):
        with pytest.raises(ValueError, match="5-field"):
            _parse_cron("0 2 *")


# ---------------------------------------------------------------------------
# run_scan_job with mocked scanner
# ---------------------------------------------------------------------------


class TestRunScanJob:
    @pytest.fixture()
    def setup(self, tmp_path: Path):
        """Set up DB, config, and a host."""
        db_path = tmp_path / "test.db"
        engine = create_db_engine(db_path)
        run_migrations(engine)

        config = Config.model_validate({
            "database": {"path": str(db_path)},
            "hosts": {"addresses": ["10.0.0.1"]},
            "scanner": {"require_root": False},
        })

        factory = create_session_factory(engine)
        session = factory()
        sync_hosts_from_config(session, config)
        session.close()

        return engine, config

    @patch("periscan.scheduler.jobs._create_scanner")
    def test_scan_job_pipeline(self, mock_create, setup):
        engine, config = setup

        # Mock scanner to return predictable results
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            hosts=[HostResult(
                ip_address="10.0.0.1",
                ports=[
                    PortResult(port=22, protocol="tcp", state=PSEnum.OPEN, service_name="ssh"),
                    PortResult(port=80, protocol="tcp", state=PSEnum.OPEN, service_name="http"),
                ],
            )],
            scan_type="quick",
            port_range="1-1024",
            scanner_tool="nmap",
        )
        mock_create.return_value = mock_scanner

        job = run_scan_job(engine, config, "quick", triggered_by="manual")

        assert job.status == "completed"
        assert job.hosts_scanned == 1
        assert job.scan_type == "quick"

        # Verify changes were detected
        factory = create_session_factory(engine)
        session = factory()
        changes = session.query(ChangeEvent).all()
        assert len(changes) == 2
        ports = {c.port for c in changes}
        assert ports == {22, 80}

        # Verify port states stored
        states = session.query(PortState).all()
        assert len(states) == 2
        session.close()

    @patch("periscan.scheduler.jobs._create_scanner")
    def test_scan_job_with_notifier(self, mock_create, setup):
        engine, config = setup

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            hosts=[HostResult(
                ip_address="10.0.0.1",
                ports=[PortResult(port=22, protocol="tcp", state=PSEnum.OPEN)],
            )],
            scan_type="quick",
            port_range="1-1024",
            scanner_tool="nmap",
        )
        mock_create.return_value = mock_scanner

        fake_notifier = MagicMock(spec=BaseNotifier)
        fake_notifier.channel_name = "test"
        fake_notifier.notify.return_value = True

        run_scan_job(engine, config, "quick", notifiers=[fake_notifier])
        fake_notifier.notify.assert_called_once()

    @patch("periscan.scheduler.jobs._create_scanner")
    def test_scan_job_no_hosts(self, mock_create, tmp_path: Path):
        """Scan with no active hosts completes immediately."""
        db_path = tmp_path / "empty.db"
        engine = create_db_engine(db_path)
        run_migrations(engine)

        config = Config.model_validate({
            "database": {"path": str(db_path)},
            "hosts": {"addresses": ["127.0.0.1"]},
        })
        # Don't sync hosts — DB is empty

        job = run_scan_job(engine, config, "quick")
        assert job.status == "completed"
        assert job.hosts_scanned == 0
        mock_create.assert_not_called()

    @patch("periscan.scheduler.jobs._create_scanner")
    def test_scan_job_failure(self, mock_create, setup):
        engine, config = setup

        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = RuntimeError("Scanner crashed")
        mock_create.return_value = mock_scanner

        job = run_scan_job(engine, config, "quick")
        assert job.status == "failed"
        assert "Scanner crashed" in job.error_message

    @patch("periscan.scheduler.jobs._create_scanner")
    def test_second_scan_detects_changes(self, mock_create, setup):
        """Run two scans — second one should detect port closing."""
        engine, config = setup

        # First scan: port 22 open
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            hosts=[HostResult(
                ip_address="10.0.0.1",
                ports=[PortResult(port=22, protocol="tcp", state=PSEnum.OPEN)],
            )],
            scan_type="quick",
            port_range="1-1024",
            scanner_tool="nmap",
        )
        mock_create.return_value = mock_scanner
        run_scan_job(engine, config, "quick")

        # Second scan: port 22 gone (closed)
        mock_scanner.scan.return_value = ScanResult(
            hosts=[HostResult(ip_address="10.0.0.1", ports=[])],
            scan_type="quick",
            port_range="1-1024",
            scanner_tool="nmap",
        )
        run_scan_job(engine, config, "quick")

        factory = create_session_factory(engine)
        session = factory()
        changes = session.query(ChangeEvent).all()
        # First scan: 1 change (port 22 open), Second: 1 change (port 22 closed)
        assert len(changes) == 2
        states = {c.current_state for c in changes}
        assert states == {"open", "closed"}
        session.close()


# ---------------------------------------------------------------------------
# CLI scan command
# ---------------------------------------------------------------------------


class TestCliScan:
    @pytest.fixture()
    def config_file(self, tmp_path: Path) -> Path:
        db_path = tmp_path / "test.db"
        cfg = tmp_path / "config.yaml"
        cfg.write_text(dedent(f"""\
            database:
              path: {db_path}
            hosts:
              addresses:
                - 10.0.0.1
            scanner:
              require_root: false
            notifications:
              log:
                enabled: false
        """))
        return cfg

    @patch("periscan.scheduler.jobs._create_scanner")
    def test_cli_scan(self, mock_create, config_file: Path):
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = ScanResult(
            hosts=[HostResult(
                ip_address="10.0.0.1",
                ports=[PortResult(port=22, protocol="tcp", state=PSEnum.OPEN)],
            )],
            scan_type="quick",
            port_range="1-1024",
            scanner_tool="nmap",
        )
        mock_create.return_value = mock_scanner

        from periscan.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["-c", str(config_file), "scan"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output
        assert "status=completed" in result.output
