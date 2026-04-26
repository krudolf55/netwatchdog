"""Tests for scanner base, nmap parser, masscan parser, and orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from typing import List

import pytest

from periscan.scanner.base import (
    BaseScanner,
    HostResult,
    PortResult,
    PortState,
    ScanResult,
)
from periscan.scanner.masscan_scanner import MasscanScanner
from periscan.scanner.nmap_scanner import NmapScanner
from periscan.scanner.orchestrator import ScanOrchestrator, _chunk_list


# ---------------------------------------------------------------------------
# Data structure tests
# ---------------------------------------------------------------------------


class TestPortState:
    def test_enum_values(self):
        assert PortState.OPEN == "open"
        assert PortState.CLOSED == "closed"
        assert PortState.FILTERED == "filtered"

    def test_port_result(self):
        pr = PortResult(port=22, protocol="tcp", state=PortState.OPEN, service_name="ssh")
        assert pr.port == 22
        assert pr.state == PortState.OPEN

    def test_host_result_no_error(self):
        hr = HostResult(ip_address="10.0.0.1", ports=[])
        assert not hr.is_error

    def test_host_result_with_error(self):
        hr = HostResult(ip_address="10.0.0.1", scan_error="timeout")
        assert hr.is_error

    def test_scan_result_aggregation(self):
        sr = ScanResult(
            hosts=[
                HostResult(ip_address="10.0.0.1", ports=[
                    PortResult(port=22, protocol="tcp", state=PortState.OPEN),
                ]),
                HostResult(ip_address="10.0.0.2", ports=[]),
            ],
            scan_type="quick",
            port_range="1-1024",
            scanner_tool="nmap",
        )
        assert len(sr.hosts) == 2
        assert not sr.is_error


# ---------------------------------------------------------------------------
# Chunk helper
# ---------------------------------------------------------------------------


class TestChunkList:
    def test_even_split(self):
        result = _chunk_list(["a", "b", "c", "d"], 2)
        assert result == [["a", "b"], ["c", "d"]]

    def test_uneven_split(self):
        result = _chunk_list(["a", "b", "c"], 2)
        assert result == [["a", "b"], ["c"]]

    def test_single_chunk(self):
        result = _chunk_list(["a", "b"], 10)
        assert result == [["a", "b"]]

    def test_empty(self):
        result = _chunk_list([], 5)
        assert result == []


# ---------------------------------------------------------------------------
# nmap parser tests (mocking python-nmap)
# ---------------------------------------------------------------------------


class TestNmapParser:
    """Test nmap result parsing with mocked nmap.PortScanner."""

    def _make_mock_nm(self, scan_data: dict) -> MagicMock:
        """Create a mock PortScanner with predefined scan data."""
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = list(scan_data.keys())
        for ip, data in scan_data.items():
            host_mock = MagicMock()
            host_mock.hostname.return_value = data.get("hostname", "")
            host_mock.all_protocols.return_value = [k for k in data if k != "hostname"]
            for proto in host_mock.all_protocols():
                host_mock.__getitem__ = MagicMock(side_effect=lambda k, d=data: d.get(k, {}))
            mock_nm.__getitem__ = MagicMock(side_effect=lambda k, sd=scan_data: sd[k])

            # Make host_data[proto] return port dict
            class HostData:
                def __init__(self, data):
                    self._data = data
                def hostname(self):
                    return self._data.get("hostname", "")
                def all_protocols(self):
                    return [k for k in self._data if k != "hostname"]
                def __getitem__(self, key):
                    return self._data.get(key, {})

            mock_nm.__getitem__ = MagicMock(
                side_effect=lambda k, sd=scan_data: type('H', (), {
                    'hostname': lambda self: sd[k].get("hostname", ""),
                    'all_protocols': lambda self: [p for p in sd[k] if p != "hostname"],
                    '__getitem__': lambda self, proto: sd[k].get(proto, {}),
                })()
            )
        return mock_nm

    @patch("periscan.scanner.nmap_scanner.nmap.PortScanner")
    def test_parse_single_host(self, mock_ps_class):
        mock_nm = self._make_mock_nm({
            "10.0.0.1": {
                "hostname": "router",
                "tcp": {
                    22: {"state": "open", "name": "ssh", "product": "OpenSSH"},
                    80: {"state": "closed", "name": "http", "product": ""},
                },
            },
        })
        mock_ps_class.return_value = mock_nm

        scanner = NmapScanner.__new__(NmapScanner)
        scanner._nm = mock_nm
        scanner._timing = "T4"
        scanner._require_root = False

        # Call _parse_results directly
        result = scanner._parse_results("1-1024")
        assert len(result.hosts) == 1
        assert result.hosts[0].ip_address == "10.0.0.1"
        assert result.hosts[0].hostname == "router"
        assert len(result.hosts[0].ports) == 2
        assert result.hosts[0].ports[0].port == 22
        assert result.hosts[0].ports[0].state == PortState.OPEN
        assert result.hosts[0].ports[0].service_name == "ssh"
        assert result.hosts[0].ports[1].state == PortState.CLOSED

    @patch("periscan.scanner.nmap_scanner.nmap.PortScanner")
    def test_parse_empty_results(self, mock_ps_class):
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = []
        mock_ps_class.return_value = mock_nm

        scanner = NmapScanner.__new__(NmapScanner)
        scanner._nm = mock_nm
        scanner._timing = "T4"
        scanner._require_root = False

        result = scanner._parse_results("1-1024")
        assert len(result.hosts) == 0
        assert result.scanner_tool == "nmap"


# ---------------------------------------------------------------------------
# masscan JSON parser tests
# ---------------------------------------------------------------------------


class TestMasscanParser:
    """Test masscan JSON output parsing."""

    def _parse(self, json_str: str, port_range: str = "1-1024") -> ScanResult:
        scanner = MasscanScanner.__new__(MasscanScanner)
        scanner._masscan_path = "masscan"
        scanner._rate = 10000
        return scanner._parse_json_output(json_str, port_range)

    def test_parse_single_host(self):
        json_data = """[
            {"ip": "10.0.0.1", "ports": [
                {"port": 22, "proto": "tcp", "status": {"state": "open"}},
                {"port": 80, "proto": "tcp", "status": {"state": "open"}}
            ]}
        ]"""
        result = self._parse(json_data)
        assert len(result.hosts) == 1
        assert result.hosts[0].ip_address == "10.0.0.1"
        assert len(result.hosts[0].ports) == 2
        assert result.hosts[0].ports[0].port == 22
        assert result.hosts[0].ports[0].state == PortState.OPEN

    def test_parse_multiple_hosts(self):
        json_data = """[
            {"ip": "10.0.0.1", "ports": [{"port": 22, "proto": "tcp", "status": {"state": "open"}}]},
            {"ip": "10.0.0.2", "ports": [{"port": 443, "proto": "tcp", "status": {"state": "open"}}]}
        ]"""
        result = self._parse(json_data)
        assert len(result.hosts) == 2

    def test_parse_empty(self):
        result = self._parse("")
        assert len(result.hosts) == 0
        assert not result.is_error

    def test_parse_empty_array(self):
        result = self._parse("[]")
        assert len(result.hosts) == 0

    def test_parse_trailing_comma(self):
        json_data = """[
            {"ip": "10.0.0.1", "ports": [{"port": 22, "proto": "tcp", "status": {"state": "open"}}]},
        ]"""
        result = self._parse(json_data)
        assert len(result.hosts) == 1

    def test_parse_invalid_json(self):
        result = self._parse("{not valid json")
        assert result.is_error
        assert "JSON parse error" in result.error

    def test_full_scan_type(self):
        result = self._parse("[]", port_range="1-65535")
        assert result.scan_type == "full"


# ---------------------------------------------------------------------------
# Orchestrator tests (with fake scanner)
# ---------------------------------------------------------------------------


class FakeScanner(BaseScanner):
    """A scanner that returns predictable results for testing."""

    def __init__(self, results_per_ip: dict = None):
        self._results = results_per_ip or {}
        self.scan_calls: List[tuple] = []

    def scan(self, targets, port_range="1-1024", timeout=600):
        self.scan_calls.append((targets, port_range, timeout))
        hosts = []
        for ip in targets:
            ports = self._results.get(ip, [])
            hosts.append(HostResult(ip_address=ip, ports=ports))
        return ScanResult(
            hosts=hosts,
            scan_type="quick",
            port_range=port_range,
            scanner_tool="fake",
        )


class TestOrchestrator:
    def test_single_batch(self):
        scanner = FakeScanner()
        orch = ScanOrchestrator(scanner, batch_size=50, max_workers=1)
        result = orch.run_scan(["10.0.0.1", "10.0.0.2"], "1-1024")
        assert len(result.hosts) == 2
        assert len(scanner.scan_calls) == 1  # single batch

    def test_multiple_batches(self):
        scanner = FakeScanner()
        targets = [f"10.0.0.{i}" for i in range(1, 11)]
        orch = ScanOrchestrator(scanner, batch_size=3, max_workers=2)
        result = orch.run_scan(targets, "1-1024")
        assert len(result.hosts) == 10
        assert len(scanner.scan_calls) == 4  # ceil(10/3) = 4 batches

    def test_empty_targets(self):
        scanner = FakeScanner()
        orch = ScanOrchestrator(scanner, batch_size=50)
        result = orch.run_scan([], "1-1024")
        assert len(result.hosts) == 0
        assert len(scanner.scan_calls) == 0

    def test_results_sorted_by_ip(self):
        scanner = FakeScanner()
        targets = ["10.0.0.3", "10.0.0.1", "10.0.0.2"]
        orch = ScanOrchestrator(scanner, batch_size=50)
        result = orch.run_scan(targets, "1-1024")
        ips = [h.ip_address for h in result.hosts]
        assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_error_handling(self):
        class ErrorScanner(BaseScanner):
            def scan(self, targets, port_range="1-1024", timeout=600):
                return ScanResult(
                    scanner_tool="error",
                    port_range=port_range,
                    error="Something went wrong",
                )

        orch = ScanOrchestrator(ErrorScanner(), batch_size=50)
        result = orch.run_scan(["10.0.0.1"], "1-1024")
        assert result.error is not None
        assert "Something went wrong" in result.error

    def test_with_port_results(self):
        scanner = FakeScanner(results_per_ip={
            "10.0.0.1": [
                PortResult(port=22, protocol="tcp", state=PortState.OPEN, service_name="ssh"),
                PortResult(port=80, protocol="tcp", state=PortState.OPEN, service_name="http"),
            ],
        })
        orch = ScanOrchestrator(scanner, batch_size=50)
        result = orch.run_scan(["10.0.0.1"], "1-1024")
        assert len(result.hosts[0].ports) == 2
        assert result.hosts[0].ports[0].service_name == "ssh"
