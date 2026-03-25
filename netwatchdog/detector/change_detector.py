"""Change detection — diffs scan results against stored port states."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from netwatchdog.database.models import ChangeEvent, PortHistory, PortState, ScanJob
from netwatchdog.scanner.base import HostResult, PortResult, ScanResult

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_port_range(port_range: str) -> Set[int]:
    """Parse a port range string into a set of port numbers.

    Supports: "1-1024", "22,80,443", "1-65535"
    """
    ports: Set[int] = set()
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return ports


class ChangeDetector:
    """Detects port state changes by comparing scan results to the database."""

    def __init__(self, session: Session):
        self._session = session

    def process(self, scan_result: ScanResult, scan_job: ScanJob) -> List[ChangeEvent]:
        """Process scan results and detect changes.

        For each host in the scan results:
        1. Compare current scan ports against stored port_states
        2. Record changes (new ports, state transitions, disappeared ports)
        3. Update port_states to reflect current state
        4. Append to port_history for changed ports

        Args:
            scan_result: Results from a scan operation.
            scan_job: The ScanJob record for this scan.

        Returns:
            List of newly created ChangeEvent records.
        """
        scanned_port_range = _parse_port_range(scan_result.port_range)
        all_changes: List[ChangeEvent] = []

        # Build a lookup: ip -> host_id
        from netwatchdog.database.models import Host
        hosts_by_ip = {
            h.ip_address: h.id
            for h in self._session.query(Host).filter_by(active=1).all()
        }

        for host_result in scan_result.hosts:
            host_id = hosts_by_ip.get(host_result.ip_address)
            if host_id is None:
                logger.warning(
                    "Scan returned results for unknown host %s, skipping",
                    host_result.ip_address,
                )
                continue

            changes = self._process_host(
                host_id=host_id,
                host_result=host_result,
                scan_job=scan_job,
                scanned_ports=scanned_port_range,
            )
            all_changes.extend(changes)

        self._session.commit()
        logger.info(
            "Change detection complete: %d change(s) across %d host(s)",
            len(all_changes), len(scan_result.hosts),
        )
        return all_changes

    def _process_host(
        self,
        host_id: int,
        host_result: HostResult,
        scan_job: ScanJob,
        scanned_ports: Set[int],
    ) -> List[ChangeEvent]:
        """Process scan results for a single host."""
        now = _now()
        changes: List[ChangeEvent] = []

        # Load current port states for this host
        existing_states = {
            (ps.port, ps.protocol): ps
            for ps in self._session.query(PortState).filter_by(host_id=host_id).all()
        }

        # Track which (port, protocol) combos we've seen in this scan
        seen_in_scan: Set[Tuple[int, str]] = set()

        # Phase 1: Process ports found in the scan
        for port_result in host_result.ports:
            key = (port_result.port, port_result.protocol)
            seen_in_scan.add(key)
            existing = existing_states.get(key)

            if existing is None:
                # New port — never seen before
                if port_result.state.value != "closed":
                    # Only record non-closed as a change (new open/filtered port)
                    change = self._record_change(
                        host_id=host_id,
                        port=port_result.port,
                        protocol=port_result.protocol,
                        previous_state=None,
                        current_state=port_result.state.value,
                        previous_service=None,
                        current_service=port_result.service_name,
                        scan_job=scan_job,
                        now=now,
                    )
                    changes.append(change)

                # Create new port_state
                ps = PortState(
                    host_id=host_id,
                    port=port_result.port,
                    protocol=port_result.protocol,
                    state=port_result.state.value,
                    service_name=port_result.service_name,
                    service_info=port_result.service_info,
                    scan_job_id=scan_job.id,
                    last_seen_at=now,
                )
                self._session.add(ps)

                # Record history
                self._record_history(host_id, port_result, scan_job, now)

            else:
                # Known port — check for state change
                old_state = existing.state
                new_state = port_result.state.value

                if old_state != new_state:
                    change = self._record_change(
                        host_id=host_id,
                        port=port_result.port,
                        protocol=port_result.protocol,
                        previous_state=old_state,
                        current_state=new_state,
                        previous_service=existing.service_name,
                        current_service=port_result.service_name,
                        scan_job=scan_job,
                        now=now,
                    )
                    changes.append(change)

                    # Record history on change
                    self._record_history(host_id, port_result, scan_job, now)

                # Update existing port_state (heartbeat)
                existing.state = new_state
                existing.service_name = port_result.service_name
                existing.service_info = port_result.service_info
                existing.scan_job_id = scan_job.id
                existing.last_seen_at = now

        # Phase 2: Handle ports NOT in scan results but within scanned range
        for (port, protocol), ps in existing_states.items():
            if (port, protocol) in seen_in_scan:
                continue
            if port not in scanned_ports:
                continue  # Port outside scan range — don't mark as closed

            # Port was previously known but not seen in this scan
            if ps.state != "closed":
                change = self._record_change(
                    host_id=host_id,
                    port=port,
                    protocol=protocol,
                    previous_state=ps.state,
                    current_state="closed",
                    previous_service=ps.service_name,
                    current_service=None,
                    scan_job=scan_job,
                    now=now,
                )
                changes.append(change)

                # Record history
                self._session.add(PortHistory(
                    host_id=host_id,
                    port=port,
                    protocol=protocol,
                    state="closed",
                    scan_job_id=scan_job.id,
                    observed_at=now,
                ))

                # Update port_state
                ps.state = "closed"
                ps.service_name = None
                ps.service_info = None
                ps.scan_job_id = scan_job.id
                ps.last_seen_at = now

        return changes

    def _record_change(
        self,
        host_id: int,
        port: int,
        protocol: str,
        previous_state: Optional[str],
        current_state: str,
        previous_service: Optional[str],
        current_service: Optional[str],
        scan_job: ScanJob,
        now: str,
    ) -> ChangeEvent:
        """Create and add a ChangeEvent to the session."""
        change = ChangeEvent(
            host_id=host_id,
            port=port,
            protocol=protocol,
            previous_state=previous_state,
            current_state=current_state,
            previous_service=previous_service,
            current_service=current_service,
            scan_job_id=scan_job.id,
            detected_at=now,
        )
        self._session.add(change)
        logger.info(
            "Change detected: host_id=%d port=%d/%s %s -> %s",
            host_id, port, protocol,
            previous_state or "NEW", current_state,
        )
        return change

    def _record_history(
        self,
        host_id: int,
        port_result: PortResult,
        scan_job: ScanJob,
        now: str,
    ) -> None:
        """Append a port_history record."""
        self._session.add(PortHistory(
            host_id=host_id,
            port=port_result.port,
            protocol=port_result.protocol,
            state=port_result.state.value,
            service_name=port_result.service_name,
            service_info=port_result.service_info,
            scan_job_id=scan_job.id,
            observed_at=now,
        ))
