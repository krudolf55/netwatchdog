"""Abstract scanner interface and shared data structures."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class PortState(str, Enum):
    """Possible states for a scanned port."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class PortResult:
    """Result for a single port on a single host."""
    port: int
    protocol: str  # "tcp" or "udp"
    state: PortState
    service_name: Optional[str] = None
    service_info: Optional[str] = None


@dataclass
class HostResult:
    """Scan results for a single host."""
    ip_address: str
    ports: List[PortResult] = field(default_factory=list)
    hostname: Optional[str] = None
    scan_error: Optional[str] = None

    @property
    def is_error(self) -> bool:
        return self.scan_error is not None


@dataclass
class ScanResult:
    """Aggregated results from a scan operation."""
    hosts: List[HostResult] = field(default_factory=list)
    scan_type: str = "quick"  # "quick" or "full"
    port_range: str = ""  # e.g. "1-1024" or "1-65535"
    scanner_tool: str = ""  # "nmap" or "masscan"
    error: Optional[str] = None

    @property
    def is_error(self) -> bool:
        return self.error is not None


class BaseScanner(ABC):
    """Abstract base class for port scanners."""

    @abstractmethod
    def scan(
        self,
        targets: List[str],
        port_range: str = "1-1024",
        timeout: int = 600,
    ) -> ScanResult:
        """Scan the given IP addresses and return results.

        Args:
            targets: List of IP addresses to scan.
            port_range: Port range string (e.g. "1-1024", "1-65535", "22,80,443").
            timeout: Maximum time in seconds for the scan.

        Returns:
            ScanResult with per-host port findings.
        """
        ...
