"""Scan job functions invoked by the scheduler."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from netwatchdog.config import Config
from netwatchdog.database.connection import create_session_factory
from netwatchdog.database.models import ChangeEvent, Host, ScanJob
from netwatchdog.detector.change_detector import ChangeDetector
from netwatchdog.notifier.base import BaseNotifier
from netwatchdog.notifier.dispatcher import NotificationDispatcher
from netwatchdog.scanner.base import ScanResult
from netwatchdog.scanner.nmap_scanner import NmapScanner
from netwatchdog.scanner.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _create_scanner(config: Config) -> NmapScanner:
    """Create scanner from config. Currently nmap only."""
    return NmapScanner(
        nmap_path=config.scanner.nmap_path,
        timing=config.scanner.nmap_timing,
        require_root=config.scanner.require_root,
    )


def run_scan_job(
    engine: Engine,
    config: Config,
    scan_type: str,
    triggered_by: str = "scheduler",
    notifiers: Optional[List[BaseNotifier]] = None,
) -> ScanJob:
    """Execute a full scan pipeline: scan -> detect changes -> notify.

    Args:
        engine: SQLAlchemy engine.
        config: Application config.
        scan_type: "quick" or "full".
        triggered_by: "scheduler" or "manual".
        notifiers: List of notification channels. If None, no notifications sent.

    Returns:
        The completed ScanJob record.
    """
    factory = create_session_factory(engine)
    session = factory(expire_on_commit=False)

    # Determine port range
    if scan_type == "full":
        port_range = config.scanner.full_ports
    else:
        port_range = config.scanner.quick_ports

    # Create scan job record
    scan_job = ScanJob(
        scan_type=scan_type,
        status="running",
        triggered_by=triggered_by,
        started_at=_now(),
        ports_scanned=json.dumps({"range": port_range}),
        created_at=_now(),
    )
    session.add(scan_job)
    session.commit()

    logger.info("Starting %s scan (job_id=%d, ports=%s)", scan_type, scan_job.id, port_range)

    try:
        # Get active hosts
        hosts = session.query(Host).filter_by(active=1).all()
        if not hosts:
            logger.warning("No active hosts to scan")
            scan_job.status = "completed"
            scan_job.completed_at = _now()
            scan_job.hosts_scanned = 0
            session.commit()
            session.close()
            return scan_job

        target_ips = [h.ip_address for h in hosts]

        # Create scanner and orchestrator
        scanner = _create_scanner(config)
        orchestrator = ScanOrchestrator.from_config(scanner, config.scanner)

        # Run the scan
        scan_result = orchestrator.run_scan(target_ips, port_range, scan_type)

        if scan_result.is_error:
            logger.error("Scan completed with errors: %s", scan_result.error)

        # Detect changes
        detector = ChangeDetector(session)
        changes = detector.process(scan_result, scan_job)

        # Update scan job
        scan_job.status = "completed"
        scan_job.completed_at = _now()
        scan_job.hosts_scanned = len(scan_result.hosts)
        if scan_result.error:
            scan_job.error_message = scan_result.error
        session.commit()

        logger.info(
            "Scan complete: job_id=%d, hosts=%d, changes=%d",
            scan_job.id, len(scan_result.hosts), len(changes),
        )

        # Notify
        if notifiers and changes:
            dispatcher = NotificationDispatcher(session, notifiers)
            dispatcher.dispatch(changes)

    except Exception as e:
        logger.exception("Scan job %d failed: %s", scan_job.id, e)
        scan_job.status = "failed"
        scan_job.completed_at = _now()
        scan_job.error_message = str(e)
        session.commit()

    finally:
        session.close()

    return scan_job
