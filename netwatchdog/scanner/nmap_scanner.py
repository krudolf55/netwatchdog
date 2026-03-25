"""nmap scanner wrapper using python-nmap."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

import nmap

from netwatchdog.scanner.base import (
    BaseScanner,
    HostResult,
    PortResult,
    PortState,
    ScanResult,
)

logger = logging.getLogger(__name__)

# Map nmap state strings to our PortState enum
_STATE_MAP = {
    "open": PortState.OPEN,
    "closed": PortState.CLOSED,
    "filtered": PortState.FILTERED,
    "unfiltered": PortState.UNFILTERED,
    "open|filtered": PortState.OPEN_FILTERED,
}


class NmapScanner(BaseScanner):
    """Port scanner using nmap via python-nmap."""

    def __init__(
        self,
        nmap_path: Optional[Path] = None,
        timing: str = "T4",
        require_root: bool = True,
    ):
        search_path = str(nmap_path) if nmap_path else None
        try:
            self._nm = nmap.PortScanner(nmap_search_path=(search_path,) if search_path else nmap.PortScanner()._nmap_search_path)
        except nmap.PortScannerError as e:
            raise RuntimeError(f"nmap not found: {e}") from e

        self._timing = timing
        self._require_root = require_root

    def scan(
        self,
        targets: List[str],
        port_range: str = "1-1024",
        timeout: int = 600,
    ) -> ScanResult:
        """Run nmap scan against the given targets."""
        target_str = " ".join(targets)

        # Build nmap arguments
        args = f"-p {port_range} -{self._timing} --host-timeout {timeout}s"
        if self._require_root:
            args += " -sS -sV"  # SYN scan + version detection (needs root)
        else:
            args += " -sT -sV"  # TCP connect scan + version detection

        logger.info(
            "Starting nmap scan: targets=%d, ports=%s, args=%s",
            len(targets), port_range, args,
        )

        try:
            self._nm.scan(hosts=target_str, arguments=args)
        except nmap.PortScannerError as e:
            logger.error("nmap scan failed: %s", e)
            return ScanResult(
                scan_type="quick" if port_range != "1-65535" else "full",
                port_range=port_range,
                scanner_tool="nmap",
                error=str(e),
            )

        return self._parse_results(port_range)

    def _parse_results(self, port_range: str) -> ScanResult:
        """Parse nmap scan results into our data structures."""
        host_results: List[HostResult] = []

        for host_ip in self._nm.all_hosts():
            host_data = self._nm[host_ip]
            hostname = None
            if host_data.hostname():
                hostname = host_data.hostname()

            ports: List[PortResult] = []
            for proto in host_data.all_protocols():
                if proto not in ("tcp", "udp"):
                    continue
                for port_num in sorted(host_data[proto].keys()):
                    port_info = host_data[proto][port_num]
                    state_str = port_info.get("state", "")
                    state = _STATE_MAP.get(state_str)
                    if state is None:
                        logger.warning(
                            "Unknown port state '%s' for %s:%d/%s",
                            state_str, host_ip, port_num, proto,
                        )
                        continue

                    ports.append(PortResult(
                        port=port_num,
                        protocol=proto,
                        state=state,
                        service_name=port_info.get("name") or None,
                        service_info=port_info.get("product") or None,
                    ))

            host_results.append(HostResult(
                ip_address=host_ip,
                ports=ports,
                hostname=hostname,
            ))

        scan_type = "full" if port_range == "1-65535" else "quick"
        return ScanResult(
            hosts=host_results,
            scan_type=scan_type,
            port_range=port_range,
            scanner_tool="nmap",
        )
