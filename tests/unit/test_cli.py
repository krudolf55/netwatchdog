"""Tests for the CLI commands."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from netwatchdog.cli import cli


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    """Create a minimal config file pointing at a temp DB."""
    db_path = tmp_path / "test.db"
    cfg = tmp_path / "config.yaml"
    cfg.write_text(dedent(f"""\
        database:
          path: {db_path}
        hosts:
          addresses:
            - 10.0.0.1
    """))
    return cfg


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_init_db(runner: CliRunner, config_file: Path):
    result = runner.invoke(cli, ["-c", str(config_file), "init-db"])
    assert result.exit_code == 0
    assert "Applied 1 migration" in result.output


def test_init_db_idempotent(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "init-db"])
    assert result.exit_code == 0
    assert "already up to date" in result.output


def test_add_single_host(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "add-host", "192.168.1.1"])
    assert result.exit_code == 0
    assert "Added 1 host" in result.output


def test_add_host_with_label(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "add-host", "192.168.1.1", "-l", "Router"])
    assert result.exit_code == 0
    assert "Added 1" in result.output

    result = runner.invoke(cli, ["-c", str(config_file), "list-hosts"])
    assert "Router" in result.output


def test_add_cidr(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "add-host", "10.0.0.0/30"])
    assert result.exit_code == 0
    assert "Added 2 host" in result.output


def test_add_duplicate_skipped(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    runner.invoke(cli, ["-c", str(config_file), "add-host", "192.168.1.1"])
    result = runner.invoke(cli, ["-c", str(config_file), "add-host", "192.168.1.1"])
    assert "skipped 1 duplicate" in result.output


def test_remove_host(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    runner.invoke(cli, ["-c", str(config_file), "add-host", "192.168.1.1"])
    result = runner.invoke(cli, ["-c", str(config_file), "remove-host", "192.168.1.1"])
    assert result.exit_code == 0
    assert "Removed 1" in result.output


def test_list_hosts_empty(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "list-hosts"])
    assert "No hosts configured" in result.output


def test_list_hosts(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    runner.invoke(cli, ["-c", str(config_file), "add-host", "10.0.0.1", "-l", "Switch"])
    runner.invoke(cli, ["-c", str(config_file), "add-host", "10.0.0.2"])
    result = runner.invoke(cli, ["-c", str(config_file), "list-hosts"])
    assert "10.0.0.1" in result.output
    assert "Switch" in result.output
    assert "Total: 2" in result.output


def test_status(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    runner.invoke(cli, ["-c", str(config_file), "add-host", "10.0.0.1"])
    result = runner.invoke(cli, ["-c", str(config_file), "status"])
    assert result.exit_code == 0
    assert "Active hosts:    1" in result.output
    assert "Open ports:      0" in result.output
    assert "Last scan:       none" in result.output
