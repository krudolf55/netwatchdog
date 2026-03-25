"""IP address and CIDR range utilities."""

from __future__ import annotations

import ipaddress
import re


def expand_target(target: str) -> list[str]:
    """Expand a target string into a list of individual IP addresses.

    Supports:
      - Single IP: "192.168.1.1"
      - CIDR notation: "192.168.1.0/24"
      - Dash range: "10.0.0.1-10.0.0.50"
    """
    target = target.strip()

    # CIDR notation
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]

    # Dash range
    if "-" in target:
        parts = target.split("-", 1)
        start = ipaddress.ip_address(parts[0].strip())
        end = ipaddress.ip_address(parts[1].strip())
        if end < start:
            raise ValueError(f"Invalid range: {target} (end < start)")
        result = []
        current = start
        while current <= end:
            result.append(str(current))
            current = ipaddress.ip_address(int(current) + 1)
        return result

    # Single IP
    addr = ipaddress.ip_address(target)
    return [str(addr)]


def validate_ip(ip: str) -> str:
    """Validate and normalize a single IP address string."""
    return str(ipaddress.ip_address(ip.strip()))
