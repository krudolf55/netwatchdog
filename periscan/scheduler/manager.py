"""APScheduler setup and lifecycle management."""

from __future__ import annotations

import logging
import signal
import threading
from typing import List, Optional

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, JobEvent
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.engine import Engine

from periscan.config import Config
from periscan.notifier.base import BaseNotifier
from periscan.scheduler.jobs import run_scan_job

logger = logging.getLogger(__name__)


def _parse_cron(cron_expr: str) -> CronTrigger:
    """Parse a 5-field cron expression into an APScheduler CronTrigger."""
    fields = cron_expr.strip().split()
    if len(fields) != 5:
        raise ValueError(f"Expected 5-field cron expression, got: {cron_expr}")
    minute, hour, day, month, day_of_week = fields
    return CronTrigger(
        minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week,
    )


def _job_listener(event: JobEvent) -> None:
    """Log scheduler job execution results."""
    if event.exception:
        logger.error("Scheduled job %s failed: %s", event.job_id, event.exception)
    else:
        logger.info("Scheduled job %s completed successfully", event.job_id)


class SchedulerManager:
    """Manages the APScheduler lifecycle and job registration."""

    def __init__(
        self,
        engine: Engine,
        config: Config,
        notifiers: Optional[List[BaseNotifier]] = None,
    ):
        self._engine = engine
        self._config = config
        self._notifiers = notifiers or []
        self._scheduler = BackgroundScheduler(
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": 3600,
            }
        )
        self._scheduler.add_listener(_job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)
        self._stop_event = threading.Event()

    def _register_jobs(self) -> None:
        """Register scan jobs based on config."""
        schedule = self._config.schedule

        if schedule.quick_scan.enabled:
            trigger = _parse_cron(schedule.quick_scan.cron)
            self._scheduler.add_job(
                run_scan_job,
                trigger=trigger,
                id="quick_scan",
                name="Quick port scan",
                replace_existing=True,
                kwargs={
                    "engine": self._engine,
                    "config": self._config,
                    "scan_type": "quick",
                    "triggered_by": "scheduler",
                    "notifiers": self._notifiers,
                },
            )
            logger.info("Registered quick scan: %s", schedule.quick_scan.cron)

        if schedule.full_scan.enabled:
            trigger = _parse_cron(schedule.full_scan.cron)
            self._scheduler.add_job(
                run_scan_job,
                trigger=trigger,
                id="full_scan",
                name="Full port scan",
                replace_existing=True,
                kwargs={
                    "engine": self._engine,
                    "config": self._config,
                    "scan_type": "full",
                    "triggered_by": "scheduler",
                    "notifiers": self._notifiers,
                },
            )
            logger.info("Registered full scan: %s", schedule.full_scan.cron)

    def start(self) -> None:
        """Start the scheduler and block until stopped."""
        self._register_jobs()
        self._scheduler.start()

        # Print next run times
        for job in self._scheduler.get_jobs():
            logger.info("Job '%s' next run: %s", job.name, job.next_run_time)

        logger.info("Scheduler started. Press Ctrl+C to stop.")

        # Handle signals for graceful shutdown
        def _signal_handler(signum, frame):  # type: ignore[no-untyped-def]
            logger.info("Received signal %d, shutting down...", signum)
            self.stop()

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        # Block until stop is called
        self._stop_event.wait()

    def stop(self) -> None:
        """Gracefully stop the scheduler."""
        self._scheduler.shutdown(wait=True)
        self._stop_event.set()
        logger.info("Scheduler stopped.")

    def run_now(self, scan_type: str = "quick") -> None:
        """Trigger an immediate scan (outside of the scheduler)."""
        run_scan_job(
            engine=self._engine,
            config=self._config,
            scan_type=scan_type,
            triggered_by="manual",
            notifiers=self._notifiers,
        )

    def get_next_run_times(self) -> dict:
        """Return next run times for all scheduled jobs."""
        return {
            job.id: str(job.next_run_time) if job.next_run_time else None
            for job in self._scheduler.get_jobs()
        }
