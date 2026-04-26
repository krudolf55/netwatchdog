"""JSON Lines log file notifier."""

from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List

from periscan.database.models import ChangeEvent, Host
from periscan.notifier.base import BaseNotifier

logger = logging.getLogger(__name__)


class LogNotifier(BaseNotifier):
    """Writes change events as JSON Lines to a rotating log file."""

    def __init__(self, log_path: Path, rotate_mb: int = 100, backup_count: int = 5):
        self._log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)

        self._handler = RotatingFileHandler(
            str(log_path),
            maxBytes=rotate_mb * 1024 * 1024,
            backupCount=backup_count,
        )
        self._change_logger = logging.getLogger("periscan.changes")
        self._change_logger.addHandler(self._handler)
        self._change_logger.setLevel(logging.INFO)
        # Prevent propagation to avoid duplicate output
        self._change_logger.propagate = False

    @property
    def channel_name(self) -> str:
        return "log"

    def notify(self, changes: List[ChangeEvent]) -> bool:
        """Write each change event as a JSON line."""
        try:
            for change in changes:
                host_ip = ""
                if change.host and hasattr(change.host, "ip_address"):
                    host_ip = change.host.ip_address

                record = {
                    "event": "port_change",
                    "host_ip": host_ip,
                    "port": change.port,
                    "protocol": change.protocol,
                    "previous_state": change.previous_state,
                    "current_state": change.current_state,
                    "previous_service": change.previous_service,
                    "current_service": change.current_service,
                    "detected_at": change.detected_at,
                    "scan_job_id": change.scan_job_id,
                }
                self._change_logger.info(json.dumps(record))

            logger.info("Wrote %d change(s) to %s", len(changes), self._log_path)
            return True
        except Exception as e:
            logger.error("Failed to write changes to log: %s", e)
            return False
