"""masscan scanner wrapper using subprocess + JSON output."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from periscan.scanner.base import (
    BaseScanner,
    HostResult,
    PortResult,
    PortState,
    ScanResult,
)

logger = logging.getLogger(__name__)

# masscan state mapping (masscan mostly reports "open")
_STATE_MAP = {
    "open": PortState.OPEN,
    "closed": PortState.CLOSED,
}


class MasscanScanner(BaseScanner):
    """Fast port scanner using masscan via subprocess."""

    def __init__(
        self,
        masscan_path: Optional[Path] = None,
        rate: int = 10000,
    ):
        self._masscan_path = str(masscan_path) if masscan_path else "masscan"
        self._rate = rate

        # Verify masscan is available
        try:
            result = subprocess.run(
                [self._masscan_path, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(f"masscan check failed: {result.stderr}")
        except FileNotFoundError:
            raise RuntimeError(f"masscan not found at: {self._masscan_path}")

    def scan(
        self,
        targets: List[str],
        port_range: str = "1-1024",
        timeout: int = 600,
    ) -> ScanResult:
        """Run masscan against the given targets.

        masscan is optimized for speed across large port ranges.
        It does NOT provide service detection — use nmap for follow-up.
        """
        target_str = ",".join(targets)

        cmd = [
            self._masscan_path,
            target_str,
            "-p", port_range,
            "--rate", str(self._rate),
            "--output-format", "json",
            "--output-filename", "-",  # stdout
        ]

        logger.info(
            "Starting masscan: targets=%d, ports=%s, rate=%d",
            len(targets), port_range, self._rate,
        )

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("masscan timed out after %ds", timeout)
            return ScanResult(
                scan_type="full" if port_range == "1-65535" else "quick",
                port_range=port_range,
                scanner_tool="masscan",
                error=f"Scan timed out after {timeout}s",
            )
        except FileNotFoundError:
            return ScanResult(
                scan_type="full" if port_range == "1-65535" else "quick",
                port_range=port_range,
                scanner_tool="masscan",
                error="masscan binary not found",
            )

        if result.returncode != 0 and not result.stdout:
            logger.error("masscan failed: %s", result.stderr)
            return ScanResult(
                scan_type="full" if port_range == "1-65535" else "quick",
                port_range=port_range,
                scanner_tool="masscan",
                error=result.stderr.strip(),
            )

        return self._parse_json_output(result.stdout, port_range)

    def _parse_json_output(self, raw_output: str, port_range: str) -> ScanResult:
        """Parse masscan JSON output into our data structures."""
        # masscan JSON output can have trailing commas or be wrapped in []
        raw = raw_output.strip()
        if not raw or raw == "[]":
            return ScanResult(
                scan_type="full" if port_range == "1-65535" else "quick",
                port_range=port_range,
                scanner_tool="masscan",
            )

        # masscan outputs JSON array but sometimes with trailing comma before ]
        # Remove trailing comma before closing bracket (with optional whitespace)
        import re
        raw = re.sub(r",\s*]", "]", raw)

        try:
            records = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse masscan JSON: %s", e)
            return ScanResult(
                scan_type="full" if port_range == "1-65535" else "quick",
                port_range=port_range,
                scanner_tool="masscan",
                error=f"JSON parse error: {e}",
            )

        # Group by IP
        hosts_map: Dict[str, List[PortResult]] = {}
        for record in records:
            ip = record.get("ip")
            if not ip:
                continue
            for port_info in record.get("ports", []):
                port_num = port_info.get("port")
                proto = port_info.get("proto", "tcp")
                state_str = port_info.get("status", {}).get("state", "open")
                state = _STATE_MAP.get(state_str, PortState.OPEN)

                hosts_map.setdefault(ip, []).append(PortResult(
                    port=port_num,
                    protocol=proto,
                    state=state,
                    # masscan doesn't provide service info
                    service_name=None,
                    service_info=None,
                ))

        host_results = [
            HostResult(ip_address=ip, ports=sorted(ports, key=lambda p: p.port))
            for ip, ports in sorted(hosts_map.items())
        ]

        scan_type = "full" if port_range == "1-65535" else "quick"
        return ScanResult(
            hosts=host_results,
            scan_type=scan_type,
            port_range=port_range,
            scanner_tool="masscan",
        )
