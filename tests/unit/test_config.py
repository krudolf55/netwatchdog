"""Tests for config loading and validation."""

import os
import textwrap
from pathlib import Path

import pytest

from netwatchdog.config import Config, load_config


def write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "netwatchdog.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def test_defaults_without_file():
    """Config loads with all defaults when no file exists."""
    cfg = Config.model_validate({"hosts": ["192.168.1.1"]})
    assert cfg.scanner.batch_size == 50
    assert cfg.schedule.quick_scan.cron == "0 2 * * *"
    assert cfg.web.port == 8080
    assert cfg.notifications.email.enabled is False
    assert cfg.notifications.log.enabled is True


def test_load_from_file(tmp_path: Path):
    p = write_yaml(tmp_path, """
        hosts:
          addresses:
            - 10.0.0.1
        scanner:
          batch_size: 25
          max_workers: 8
        web:
          port: 9090
    """)
    cfg = load_config(p)
    assert cfg.hosts == ["10.0.0.1"]
    assert cfg.scanner.batch_size == 25
    assert cfg.scanner.max_workers == 8
    assert cfg.web.port == 9090


def test_host_labels_parsed(tmp_path: Path):
    p = write_yaml(tmp_path, """
        hosts:
          addresses:
            - 192.168.1.1
          labels:
            192.168.1.1: "Primary Router"
    """)
    cfg = load_config(p)
    assert cfg.host_labels["192.168.1.1"] == "Primary Router"


def test_empty_hosts_raises(tmp_path: Path):
    p = write_yaml(tmp_path, """
        hosts:
          addresses: []
    """)
    with pytest.raises(Exception, match="hosts list cannot be empty"):
        load_config(p)


def test_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    p = write_yaml(tmp_path, """
        hosts:
          addresses:
            - 10.0.0.1
    """)
    monkeypatch.setenv("NETWATCHDOG__WEB__PORT", "7777")
    monkeypatch.setenv("NETWATCHDOG__SCANNER__BATCH_SIZE", "10")
    cfg = load_config(p)
    assert cfg.web.port == 7777
    assert cfg.scanner.batch_size == 10


def test_invalid_tool_raises():
    with pytest.raises(Exception):
        Config.model_validate({
            "hosts": ["10.0.0.1"],
            "scanner": {"default_tool": "invalid"},
        })


def test_invalid_timing_raises():
    with pytest.raises(Exception):
        Config.model_validate({
            "hosts": ["10.0.0.1"],
            "scanner": {"nmap_timing": "T9"},
        })
