"""Configuration loading and validation using Pydantic."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class DatabaseConfig(BaseModel):
    path: Path = Path("/var/lib/netwatchdog/netwatchdog.db")
    wal_mode: bool = True


class HostLabels(BaseModel):
    labels: Dict[str, str] = Field(default_factory=dict)


class ScannerConfig(BaseModel):
    default_tool: str = Field("auto", pattern="^(nmap|masscan|auto)$")
    require_root: bool = True
    nmap_path: Path = Path("/usr/bin/nmap")
    masscan_path: Path = Path("/usr/bin/masscan")
    batch_size: int = Field(50, ge=1, le=1000)
    max_workers: int = Field(4, ge=1, le=32)
    masscan_rate: int = Field(10000, ge=100, le=1000000)
    nmap_timing: str = Field("T4", pattern="^T[0-5]$")
    quick_ports: str = "1-1024"
    full_ports: str = "1-65535"
    timeout_per_batch: int = Field(600, ge=30)


class ScanScheduleEntry(BaseModel):
    enabled: bool = True
    cron: str  # standard 5-field cron expression


class ScheduleConfig(BaseModel):
    quick_scan: ScanScheduleEntry = ScanScheduleEntry(cron="0 2 * * *")
    full_scan: ScanScheduleEntry = ScanScheduleEntry(cron="0 3 * * 0")


class WebAuthConfig(BaseModel):
    enabled: bool = False
    username: str = "admin"
    password: str = "changeme"


class WebConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(8080, ge=1, le=65535)
    secret_key: str = "changeme-set-a-real-secret"
    debug: bool = False
    auth: WebAuthConfig = WebAuthConfig()


class EmailConfig(BaseModel):
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_use_tls: bool = True
    smtp_username: str = ""
    smtp_password: str = ""
    from_address: str = ""
    to_addresses: List[str] = Field(default_factory=list)
    batch_changes: bool = True
    min_severity: str = Field("any", pattern="^(any|open_only)$")


class LogNotifierConfig(BaseModel):
    enabled: bool = True
    path: Path = Path("/var/log/netwatchdog/changes.jsonl")
    rotate_mb: int = Field(100, ge=1)
    backup_count: int = Field(5, ge=0)


class NotificationsConfig(BaseModel):
    email: EmailConfig = EmailConfig()
    log: LogNotifierConfig = LogNotifierConfig()


class LoggingConfig(BaseModel):
    level: str = Field("INFO", pattern="^(DEBUG|INFO|WARNING|ERROR)$")
    format: str = Field("json", pattern="^(json|text)$")
    path: Path = Path("/var/log/netwatchdog/netwatchdog.log")
    rotate_mb: int = Field(50, ge=1)
    backup_count: int = Field(10, ge=0)


# ---------------------------------------------------------------------------
# Root config model
# ---------------------------------------------------------------------------


class Config(BaseModel):
    database: DatabaseConfig = DatabaseConfig()
    hosts: List[str] = Field(default_factory=list)
    host_labels: Dict[str, str] = Field(default_factory=dict)
    scanner: ScannerConfig = ScannerConfig()
    schedule: ScheduleConfig = ScheduleConfig()
    web: WebConfig = WebConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    logging: LoggingConfig = LoggingConfig()

    @field_validator("hosts")
    @classmethod
    def hosts_not_empty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("hosts list cannot be empty")
        return v

    @model_validator(mode="before")
    @classmethod
    def extract_host_labels(cls, data: Any) -> Any:
        """Pull labels out of the hosts section if present."""
        if isinstance(data, dict) and isinstance(data.get("hosts"), dict):
            hosts_section = data["hosts"]
            data["hosts"] = hosts_section.get("addresses", [])
            data["host_labels"] = hosts_section.get("labels", {})
        return data


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_SEARCH_PATHS = [
    Path("config/netwatchdog.yaml"),
    Path.home() / ".config" / "netwatchdog" / "config.yaml",
    Path("/etc/netwatchdog/config.yaml"),
]


def _apply_env_overrides(data: Dict[str, Any]) -> Dict[str, Any]:
    """Apply NETWATCHDOG__SECTION__KEY env vars as overrides."""
    prefix = "NETWATCHDOG__"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("__")
        target = data
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    return data


def load_config(path: Optional[Path] = None) -> Config:
    """Load and validate configuration from a YAML file.

    Search order (first found wins):
      1. Explicit path argument
      2. config/netwatchdog.yaml (relative to cwd)
      3. ~/.config/netwatchdog/config.yaml
      4. /etc/netwatchdog/config.yaml

    Environment variable overrides are applied after file loading.
    """
    config_path: Optional[Path] = path
    if config_path is None:
        for candidate in _SEARCH_PATHS:
            if candidate.exists():
                config_path = candidate
                break

    raw: dict[str, Any] = {}
    if config_path is not None:
        with config_path.open() as f:
            raw = yaml.safe_load(f) or {}

    raw = _apply_env_overrides(raw)
    return Config.model_validate(raw)
