"""Sync hosts from config file into the database."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from netwatchdog.config import Config
from netwatchdog.database.models import Host
from netwatchdog.utils.ip_utils import expand_target


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def sync_hosts_from_config(session: Session, config: Config) -> dict[str, int]:
    """Sync hosts defined in the config file into the database.

    - Adds new config-defined hosts
    - Applies labels from config to config-defined hosts
    - Re-activates config-defined hosts that were previously deactivated
    - Does NOT touch CLI-added hosts
    - Does NOT remove config hosts that are no longer in config
      (they just get marked source='cli' so they can be removed manually)

    Returns dict with counts: {"added": N, "updated": N, "unchanged": N}
    """
    counts = {"added": 0, "updated": 0, "unchanged": 0}

    # Expand all config targets into individual IPs
    config_ips: set[str] = set()
    for target in config.hosts:
        config_ips.update(expand_target(target))

    # Build label lookup
    labels = config.host_labels

    for ip in sorted(config_ips):
        label = labels.get(ip)
        existing = session.query(Host).filter_by(ip_address=ip).first()

        if existing is None:
            # New host from config
            host = Host(
                ip_address=ip,
                label=label,
                source="config",
                active=1,
                created_at=_now(),
                updated_at=_now(),
            )
            session.add(host)
            counts["added"] += 1
        else:
            changed = False
            # Update source if it was CLI-added but now in config
            if existing.source != "config":
                existing.source = "config"
                changed = True
            # Re-activate if deactivated
            if not existing.active:
                existing.active = 1
                changed = True
            # Apply label from config (config label takes precedence)
            if label is not None and existing.label != label:
                existing.label = label
                changed = True
            if changed:
                existing.updated_at = _now()
                counts["updated"] += 1
            else:
                counts["unchanged"] += 1

    session.commit()
    return counts
