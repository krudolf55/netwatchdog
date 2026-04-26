"""Tests for the CLI commands."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from periscan.cli import cli


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
    assert "Applied" in result.output
    assert "Config hosts: 1 added" in result.output


def test_init_db_idempotent(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "init-db"])
    assert result.exit_code == 0
    assert "1 unchanged" in result.output


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
    # 10.0.0.0/30 expands to .1 and .2; .1 is already from config
    result = runner.invoke(cli, ["-c", str(config_file), "add-host", "10.0.0.0/30"])
    assert result.exit_code == 0
    assert "Added 1 host" in result.output
    assert "skipped 1 duplicate" in result.output


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


def test_list_hosts_empty(runner: CliRunner, tmp_path: Path):
    """Use a config with no hosts to test empty listing."""
    db_path = tmp_path / "empty.db"
    cfg = tmp_path / "empty_config.yaml"
    cfg.write_text(dedent(f"""\
        database:
          path: {db_path}
        hosts:
          addresses:
            - 127.0.0.1
    """))
    # Init, then remove the only host (it's CLI-sourced if we add manually)
    # Simpler: just create a config with a host, init, then check it shows up
    runner.invoke(cli, ["-c", str(cfg), "init-db"])
    result = runner.invoke(cli, ["-c", str(cfg), "list-hosts"])
    assert "127.0.0.1" in result.output


def test_list_hosts(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    # 10.0.0.1 already from config; add a second via CLI
    runner.invoke(cli, ["-c", str(config_file), "add-host", "10.0.0.2", "-l", "Switch"])
    result = runner.invoke(cli, ["-c", str(config_file), "list-hosts"])
    assert "10.0.0.1" in result.output
    assert "10.0.0.2" in result.output
    assert "Switch" in result.output
    assert "Total: 2" in result.output


def test_status(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "status"])
    assert result.exit_code == 0
    assert "Active hosts:    1" in result.output  # from config sync
    assert "Open ports:      0" in result.output
    assert "Last scan:       none" in result.output


def test_remove_config_host_blocked(runner: CliRunner, config_file: Path):
    runner.invoke(cli, ["-c", str(config_file), "init-db"])
    result = runner.invoke(cli, ["-c", str(config_file), "remove-host", "10.0.0.1"])
    assert "Removed 0" in result.output
    assert "config-defined" in result.output


# ---- import-hosts tests ----------------------------------------------------

def test_import_hosts_basic(runner: CliRunner, config_file: Path, tmp_path: Path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("192.168.1.1\n192.168.1.2\n192.168.1.3\n")
    result = runner.invoke(cli, ["-c", str(config_file), "import-hosts", str(hosts_file)])
    assert result.exit_code == 0
    assert "Imported 3" in result.output
    assert "0 error(s)" in result.output
    # verify written to config file
    import yaml
    data = yaml.safe_load(config_file.read_text())
    assert "192.168.1.1" in data["hosts"]["addresses"]


def test_import_hosts_skips_comments_and_blanks(runner: CliRunner, config_file: Path, tmp_path: Path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("# this is a comment\n\n192.168.1.1\n\n# another comment\n192.168.1.2\n")
    result = runner.invoke(cli, ["-c", str(config_file), "import-hosts", str(hosts_file)])
    assert "Imported 2" in result.output


def test_import_hosts_skips_duplicates(runner: CliRunner, config_file: Path, tmp_path: Path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("192.168.1.1\n")
    runner.invoke(cli, ["-c", str(config_file), "import-hosts", str(hosts_file)])
    result = runner.invoke(cli, ["-c", str(config_file), "import-hosts", str(hosts_file)])
    assert "skipped 1 duplicate(s)" in result.output


def test_import_hosts_invalid_line(runner: CliRunner, config_file: Path, tmp_path: Path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("192.168.1.1\nnot-an-ip\n192.168.1.2\n")
    result = runner.invoke(cli, ["-c", str(config_file), "import-hosts", str(hosts_file)])
    assert "Imported 2" in result.output
    assert "1 error(s)" in result.output


def test_import_hosts_cidr(runner: CliRunner, config_file: Path, tmp_path: Path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("192.168.1.0/30\n")
    result = runner.invoke(cli, ["-c", str(config_file), "import-hosts", str(hosts_file)])
    # CIDR stored as-is in config (not expanded)
    assert "Imported 1" in result.output


def test_import_hosts_trailing_comma(runner: CliRunner, config_file: Path, tmp_path: Path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("192.168.1.1,\n192.168.1.2,\n")
    result = runner.invoke(cli, ["-c", str(config_file), "import-hosts", str(hosts_file)])
    assert "Imported 2" in result.output
    assert "0 error(s)" in result.output


def test_import_hosts_requires_config(runner: CliRunner, tmp_path: Path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("192.168.1.1\n")
    result = runner.invoke(cli, ["import-hosts", str(hosts_file)])
    assert result.exit_code != 0
    assert "No config file" in result.output
