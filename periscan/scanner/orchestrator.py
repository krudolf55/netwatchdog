"""Scan orchestrator — batches IPs and runs scanners in parallel."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from periscan.config import ScannerConfig
from periscan.scanner.base import BaseScanner, HostResult, ScanResult

logger = logging.getLogger(__name__)


def _chunk_list(items: List[str], chunk_size: int) -> List[List[str]]:
    """Split a list into chunks of the given size."""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


class ScanOrchestrator:
    """Coordinates scanning across multiple IPs using batching and parallelism."""

    def __init__(
        self,
        scanner: BaseScanner,
        batch_size: int = 50,
        max_workers: int = 4,
        timeout_per_batch: int = 600,
    ):
        self._scanner = scanner
        self._batch_size = batch_size
        self._max_workers = max_workers
        self._timeout = timeout_per_batch

    @classmethod
    def from_config(cls, scanner: BaseScanner, config: ScannerConfig) -> "ScanOrchestrator":
        """Create an orchestrator from scanner config."""
        return cls(
            scanner=scanner,
            batch_size=config.batch_size,
            max_workers=config.max_workers,
            timeout_per_batch=config.timeout_per_batch,
        )

    def run_scan(
        self,
        targets: List[str],
        port_range: str = "1-1024",
        scan_type: str = "quick",
    ) -> ScanResult:
        """Scan all targets, batching and parallelizing as needed.

        Args:
            targets: List of IP addresses.
            port_range: Port range to scan.
            scan_type: "quick" or "full".

        Returns:
            Merged ScanResult containing all host results.
        """
        if not targets:
            return ScanResult(scan_type=scan_type, port_range=port_range)

        batches = _chunk_list(targets, self._batch_size)
        logger.info(
            "Orchestrator: %d targets, %d batch(es) of %d, %d workers",
            len(targets), len(batches), self._batch_size, self._max_workers,
        )

        all_hosts: List[HostResult] = []
        errors: List[str] = []

        if len(batches) == 1:
            # Single batch — no need for thread pool
            result = self._scanner.scan(batches[0], port_range, self._timeout)
            all_hosts.extend(result.hosts)
            if result.error:
                errors.append(result.error)
        else:
            # Multiple batches — run in parallel
            with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                futures = {
                    executor.submit(
                        self._scanner.scan, batch, port_range, self._timeout
                    ): i
                    for i, batch in enumerate(batches)
                }
                for future in as_completed(futures):
                    batch_idx = futures[future]
                    try:
                        result = future.result()
                        all_hosts.extend(result.hosts)
                        if result.error:
                            errors.append(f"Batch {batch_idx}: {result.error}")
                        logger.info(
                            "Batch %d complete: %d hosts scanned",
                            batch_idx, len(result.hosts),
                        )
                    except Exception as e:
                        logger.error("Batch %d failed: %s", batch_idx, e)
                        errors.append(f"Batch {batch_idx}: {e}")

        # Sort hosts by IP for consistent output
        all_hosts.sort(key=lambda h: h.ip_address)

        combined_error: Optional[str] = None
        if errors:
            combined_error = "; ".join(errors)

        return ScanResult(
            hosts=all_hosts,
            scan_type=scan_type,
            port_range=port_range,
            scanner_tool=self._scanner.__class__.__name__,
            error=combined_error,
        )
