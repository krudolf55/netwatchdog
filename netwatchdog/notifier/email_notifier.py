"""SMTP email notifier."""

from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

from netwatchdog.config import EmailConfig
from netwatchdog.database.models import ChangeEvent
from netwatchdog.notifier.base import BaseNotifier

logger = logging.getLogger(__name__)


def _build_change_summary(changes: List[ChangeEvent]) -> str:
    """Build a plain text summary of changes."""
    lines = []
    for change in changes:
        host_ip = ""
        if change.host and hasattr(change.host, "ip_address"):
            host_ip = change.host.ip_address

        prev = change.previous_state or "NEW"
        svc = ""
        if change.current_service:
            svc = f" ({change.current_service})"

        lines.append(
            f"  {host_ip}:{change.port}/{change.protocol}  "
            f"{prev} -> {change.current_state}{svc}"
        )
    return "\n".join(lines)


def _build_html_summary(changes: List[ChangeEvent]) -> str:
    """Build an HTML summary of changes."""
    rows = []
    for change in changes:
        host_ip = ""
        if change.host and hasattr(change.host, "ip_address"):
            host_ip = change.host.ip_address

        prev = change.previous_state or "NEW"
        svc = change.current_service or ""

        # Color code the state transition
        color = "#333"
        if change.current_state == "open":
            color = "#d9534f"  # red — new port open is notable
        elif change.current_state == "closed":
            color = "#5cb85c"  # green
        elif change.current_state == "filtered":
            color = "#f0ad4e"  # yellow

        rows.append(
            f"<tr>"
            f"<td>{host_ip}</td>"
            f"<td>{change.port}/{change.protocol}</td>"
            f"<td>{prev}</td>"
            f"<td style='color:{color};font-weight:bold'>{change.current_state}</td>"
            f"<td>{svc}</td>"
            f"<td>{change.detected_at}</td>"
            f"</tr>"
        )

    table_rows = "\n".join(rows)
    return f"""<html><body>
<h2>NetWatchdog Port Changes Detected</h2>
<p>{len(changes)} change(s) detected:</p>
<table border="1" cellpadding="5" cellspacing="0" style="border-collapse:collapse">
<tr style="background:#f5f5f5">
<th>Host</th><th>Port</th><th>Previous</th><th>Current</th><th>Service</th><th>Detected</th>
</tr>
{table_rows}
</table>
<p style="color:#999;font-size:12px">Sent by NetWatchdog</p>
</body></html>"""


class EmailNotifier(BaseNotifier):
    """Sends change notifications via SMTP email."""

    def __init__(self, config: EmailConfig):
        self._config = config

    @property
    def channel_name(self) -> str:
        return "email"

    def notify(self, changes: List[ChangeEvent]) -> bool:
        """Send an email with the change summary."""
        if not changes:
            return True
        if not self._config.to_addresses:
            logger.warning("No email recipients configured, skipping")
            return False

        subject = f"[NetWatchdog] {len(changes)} port change(s) detected"
        text_body = (
            f"NetWatchdog detected {len(changes)} port change(s):\n\n"
            f"{_build_change_summary(changes)}\n"
        )
        html_body = _build_html_summary(changes)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._config.from_address
        msg["To"] = ", ".join(self._config.to_addresses)
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            if self._config.smtp_use_tls:
                server = smtplib.SMTP(self._config.smtp_host, self._config.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self._config.smtp_host, self._config.smtp_port)

            if self._config.smtp_username:
                server.login(self._config.smtp_username, self._config.smtp_password)

            server.sendmail(
                self._config.from_address,
                self._config.to_addresses,
                msg.as_string(),
            )
            server.quit()

            logger.info(
                "Email sent to %s: %d change(s)",
                self._config.to_addresses, len(changes),
            )
            return True

        except Exception as e:
            logger.error("Failed to send email: %s", e)
            return False

    def send_test(self) -> bool:
        """Send a test email to verify SMTP configuration."""
        msg = MIMEText("This is a test message from NetWatchdog.")
        msg["Subject"] = "[NetWatchdog] Test notification"
        msg["From"] = self._config.from_address
        msg["To"] = ", ".join(self._config.to_addresses)

        try:
            if self._config.smtp_use_tls:
                server = smtplib.SMTP(self._config.smtp_host, self._config.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self._config.smtp_host, self._config.smtp_port)

            if self._config.smtp_username:
                server.login(self._config.smtp_username, self._config.smtp_password)

            server.sendmail(
                self._config.from_address,
                self._config.to_addresses,
                msg.as_string(),
            )
            server.quit()
            return True
        except Exception as e:
            logger.error("Test email failed: %s", e)
            return False
