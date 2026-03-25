"""Abstract notifier interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from netwatchdog.database.models import ChangeEvent


class BaseNotifier(ABC):
    """Abstract base class for change notification channels."""

    @abstractmethod
    def notify(self, changes: List[ChangeEvent]) -> bool:
        """Send notification for the given change events.

        Args:
            changes: List of ChangeEvent records to report.

        Returns:
            True if notification was sent successfully, False otherwise.
        """
        ...

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Return the name of this notification channel (e.g. 'email', 'log')."""
        ...
