"""Tests for notifiers and dispatcher."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from netwatchdog.config import EmailConfig
from netwatchdog.database.connection import create_db_engine, create_session_factory
from netwatchdog.database.migrations import run_migrations
from netwatchdog.database.models import (
    ChangeEvent,
    Host,
    NotificationLog,
    ScanJob,
)
from netwatchdog.notifier.base import BaseNotifier
from netwatchdog.notifier.dispatcher import NotificationDispatcher
from netwatchdog.notifier.email_notifier import (
    EmailNotifier,
    _build_change_summary,
    _build_html_summary,
)
from netwatchdog.notifier.log_notifier import LogNotifier


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
def sample_changes(session):
    """Create a host, scan job, and some change events."""
    host = Host(ip_address="10.0.0.1", source="cli", created_at=_now(), updated_at=_now())
    session.add(host)
    session.flush()

    job = ScanJob(scan_type="quick", status="completed", created_at=_now())
    session.add(job)
    session.flush()

    changes = [
        ChangeEvent(
            host_id=host.id, port=22, protocol="tcp",
            previous_state=None, current_state="open",
            current_service="ssh", scan_job_id=job.id, detected_at=_now(),
        ),
        ChangeEvent(
            host_id=host.id, port=80, protocol="tcp",
            previous_state="open", current_state="closed",
            previous_service="http", scan_job_id=job.id, detected_at=_now(),
        ),
    ]
    session.add_all(changes)
    session.commit()

    # Re-query to get relationship loaded
    return session.query(ChangeEvent).all()


# ---------------------------------------------------------------------------
# LogNotifier
# ---------------------------------------------------------------------------


class TestLogNotifier:
    def test_writes_json_lines(self, tmp_path: Path, sample_changes):
        log_path = tmp_path / "changes.jsonl"
        notifier = LogNotifier(log_path)
        result = notifier.notify(sample_changes)

        assert result is True
        assert log_path.exists()

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2

        record = json.loads(lines[0])
        assert record["event"] == "port_change"
        assert record["port"] == 22
        assert record["current_state"] == "open"

    def test_creates_parent_dirs(self, tmp_path: Path, sample_changes):
        log_path = tmp_path / "deep" / "nested" / "changes.jsonl"
        notifier = LogNotifier(log_path)
        notifier.notify(sample_changes)
        assert log_path.exists()

    def test_channel_name(self, tmp_path: Path):
        notifier = LogNotifier(tmp_path / "test.jsonl")
        assert notifier.channel_name == "log"

    def test_empty_changes(self, tmp_path: Path):
        notifier = LogNotifier(tmp_path / "test.jsonl")
        result = notifier.notify([])
        assert result is True


# ---------------------------------------------------------------------------
# EmailNotifier — text/HTML builders
# ---------------------------------------------------------------------------


class TestEmailSummaryBuilders:
    def test_text_summary(self, sample_changes):
        text = _build_change_summary(sample_changes)
        assert "10.0.0.1:22/tcp" in text
        assert "NEW -> open" in text
        assert "open -> closed" in text
        assert "(ssh)" in text

    def test_html_summary(self, sample_changes):
        html = _build_html_summary(sample_changes)
        assert "<html>" in html
        assert "10.0.0.1" in html
        assert "22/tcp" in html
        assert "2 change(s)" in html

    def test_html_color_coding(self, sample_changes):
        html = _build_html_summary(sample_changes)
        assert "#d9534f" in html  # red for open
        assert "#5cb85c" in html  # green for closed


class TestEmailNotifier:
    def test_channel_name(self):
        config = EmailConfig(enabled=True, from_address="a@b.com", to_addresses=["c@d.com"])
        notifier = EmailNotifier(config)
        assert notifier.channel_name == "email"

    def test_no_recipients_returns_false(self, sample_changes):
        config = EmailConfig(enabled=True, from_address="a@b.com", to_addresses=[])
        notifier = EmailNotifier(config)
        result = notifier.notify(sample_changes)
        assert result is False

    def test_empty_changes_returns_true(self):
        config = EmailConfig(enabled=True, from_address="a@b.com", to_addresses=["c@d.com"])
        notifier = EmailNotifier(config)
        result = notifier.notify([])
        assert result is True

    @patch("netwatchdog.notifier.email_notifier.smtplib.SMTP")
    def test_send_email(self, mock_smtp_class, sample_changes):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        config = EmailConfig(
            enabled=True,
            smtp_host="smtp.test.com",
            smtp_port=587,
            smtp_use_tls=True,
            smtp_username="user",
            smtp_password="pass",
            from_address="nw@test.com",
            to_addresses=["ops@test.com"],
        )
        notifier = EmailNotifier(config)
        result = notifier.notify(sample_changes)

        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user", "pass")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

        # Verify the email content
        call_args = mock_server.sendmail.call_args
        assert call_args[0][0] == "nw@test.com"
        assert call_args[0][1] == ["ops@test.com"]
        assert "port change" in call_args[0][2].lower()

    @patch("netwatchdog.notifier.email_notifier.smtplib.SMTP")
    def test_smtp_failure(self, mock_smtp_class, sample_changes):
        mock_smtp_class.side_effect = ConnectionRefusedError("Connection refused")

        config = EmailConfig(
            enabled=True,
            smtp_host="bad.host",
            smtp_port=587,
            from_address="a@b.com",
            to_addresses=["c@d.com"],
        )
        notifier = EmailNotifier(config)
        result = notifier.notify(sample_changes)
        assert result is False


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class FakeNotifier(BaseNotifier):
    def __init__(self, name: str, should_succeed: bool = True):
        self._name = name
        self._should_succeed = should_succeed
        self.received_changes: List[ChangeEvent] = []

    @property
    def channel_name(self) -> str:
        return self._name

    def notify(self, changes: List[ChangeEvent]) -> bool:
        self.received_changes.extend(changes)
        return self._should_succeed


class TestDispatcher:
    def test_dispatches_to_all_notifiers(self, session, sample_changes):
        n1 = FakeNotifier("log")
        n2 = FakeNotifier("email")
        dispatcher = NotificationDispatcher(session, [n1, n2])

        dispatcher.dispatch(sample_changes)

        assert len(n1.received_changes) == 2
        assert len(n2.received_changes) == 2

    def test_marks_changes_as_notified(self, session, sample_changes):
        notifier = FakeNotifier("log")
        dispatcher = NotificationDispatcher(session, [notifier])

        dispatcher.dispatch(sample_changes)

        for change in sample_changes:
            assert change.notified == 1

    def test_logs_notification_results(self, session, sample_changes):
        notifier = FakeNotifier("log")
        dispatcher = NotificationDispatcher(session, [notifier])

        dispatcher.dispatch(sample_changes)

        logs = session.query(NotificationLog).all()
        assert len(logs) == 1
        assert logs[0].channel == "log"
        assert logs[0].status == "sent"

    def test_logs_failure(self, session, sample_changes):
        notifier = FakeNotifier("email", should_succeed=False)
        dispatcher = NotificationDispatcher(session, [notifier])

        dispatcher.dispatch(sample_changes)

        logs = session.query(NotificationLog).all()
        assert len(logs) == 1
        assert logs[0].status == "failed"

    def test_handles_notifier_exception(self, session, sample_changes):
        class BrokenNotifier(BaseNotifier):
            @property
            def channel_name(self):
                return "broken"
            def notify(self, changes):
                raise RuntimeError("kaboom")

        dispatcher = NotificationDispatcher(session, [BrokenNotifier()])
        dispatcher.dispatch(sample_changes)  # should not raise

        logs = session.query(NotificationLog).all()
        assert len(logs) == 1
        assert logs[0].status == "failed"
        assert "kaboom" in logs[0].error_message

    def test_empty_changes_no_op(self, session):
        notifier = FakeNotifier("log")
        dispatcher = NotificationDispatcher(session, [notifier])
        dispatcher.dispatch([])
        assert len(notifier.received_changes) == 0
        assert session.query(NotificationLog).count() == 0
