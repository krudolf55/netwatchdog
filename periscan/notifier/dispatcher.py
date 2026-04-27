"""Notification dispatcher — sends changes through all enabled notifiers."""

from __future__ import annotations

import json
import logging
from typing import List

from sqlalchemy.orm import Session

from periscan.database.models import ChangeEvent, NotificationLog
from periscan.notifier.base import BaseNotifier

logger = logging.getLogger(__name__)


def _now() -> str:
    from datetime import datetime
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class NotificationDispatcher:
    """Dispatches change events through all registered notifiers."""

    def __init__(self, session: Session, notifiers: List[BaseNotifier]):
        self._session = session
        self._notifiers = notifiers

    def dispatch(self, changes: List[ChangeEvent]) -> None:
        """Send changes through all notifiers and log results.

        Marks change events as notified after all channels have been attempted.
        """
        if not changes:
            return

        change_ids = [c.id for c in changes]
        change_ids_json = json.dumps(change_ids)

        for notifier in self._notifiers:
            try:
                success = notifier.notify(changes)
                status = "sent" if success else "failed"
                error_msg = None if success else "Notifier returned False"
            except Exception as e:
                status = "failed"
                error_msg = str(e)
                logger.error(
                    "Notifier '%s' raised exception: %s",
                    notifier.channel_name, e,
                )

            log_entry = NotificationLog(
                channel=notifier.channel_name,
                change_event_ids=change_ids_json,
                status=status,
                error_message=error_msg,
                sent_at=_now(),
            )
            self._session.add(log_entry)

        # Mark all changes as notified
        for change in changes:
            change.notified = 1

        self._session.commit()
        logger.info(
            "Dispatched %d change(s) through %d notifier(s)",
            len(changes), len(self._notifiers),
        )
