"""CLI entry point for netwatchdog."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from netwatchdog.config import load_config
from netwatchdog.database.connection import create_db_engine, create_session_factory
from netwatchdog.database.migrations import run_migrations
from netwatchdog.database.models import Host
from netwatchdog.database.sync import sync_hosts_from_config
from netwatchdog.utils.ip_utils import expand_target, validate_ip


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


@click.group()
@click.option(
    "--config", "-c", "config_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to config YAML file.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[Path]) -> None:
    """netwatchdog — Network port change monitoring."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


def _get_session(ctx: click.Context):
    """Load config, create engine, and return a session."""
    cfg = load_config(ctx.obj.get("config_path"))
    engine = create_db_engine(cfg.database.path, wal_mode=cfg.database.wal_mode)
    factory = create_session_factory(engine)
    return cfg, engine, factory()


# ---- init-db ---------------------------------------------------------------

@cli.command("init-db")
@click.pass_context
def init_db(ctx: click.Context) -> None:
    """Initialize the database, run migrations, and sync hosts from config."""
    cfg = load_config(ctx.obj.get("config_path"))
    engine = create_db_engine(cfg.database.path, wal_mode=cfg.database.wal_mode)
    applied = run_migrations(engine)
    if applied:
        click.echo(f"Applied {len(applied)} migration(s): {applied}")
    else:
        click.echo("Database is already up to date.")

    # Sync hosts from config file
    if cfg.hosts:
        factory = create_session_factory(engine)
        session = factory()
        counts = sync_hosts_from_config(session, cfg)
        session.close()
        click.echo(
            f"Config hosts: {counts['added']} added, "
            f"{counts['updated']} updated, "
            f"{counts['unchanged']} unchanged."
        )

    click.echo(f"Database: {cfg.database.path}")


# ---- add-host --------------------------------------------------------------

@cli.command("add-host")
@click.argument("target")
@click.option("--label", "-l", default=None, help="Label for the host(s).")
@click.pass_context
def add_host(ctx: click.Context, target: str, label: Optional[str]) -> None:
    """Add host(s) to monitor. Accepts single IP, CIDR, or dash range."""
    cfg, engine, session = _get_session(ctx)
    run_migrations(engine)

    try:
        ips = expand_target(target)
    except ValueError as e:
        raise click.ClickException(str(e))

    added = 0
    skipped = 0
    for ip in ips:
        existing = session.query(Host).filter_by(ip_address=ip).first()
        if existing:
            skipped += 1
            continue
        host = Host(
            ip_address=ip,
            label=label,
            source="cli",
            created_at=_now(),
            updated_at=_now(),
        )
        session.add(host)
        added += 1

    session.commit()
    session.close()
    click.echo(f"Added {added} host(s), skipped {skipped} duplicate(s).")


# ---- import-hosts ----------------------------------------------------------

@cli.command("import-hosts")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def import_hosts(ctx: click.Context, file: Path) -> None:
    """Import hosts from a text file into the config file (one entry per line).

    Each line may be a single IP, CIDR range, or dash range:

    \b
        192.168.1.1
        10.0.0.0/24
        10.1.0.1-10.1.0.50
    Blank lines and lines starting with # are ignored.
    Restart the service after importing to pick up the changes.
    """
    import yaml

    config_path = ctx.obj.get("config_path")
    if config_path is None:
        raise click.ClickException(
            "No config file specified. Use: netwatchdog --config /path/to/config.yaml import-hosts ..."
        )

    raw = yaml.safe_load(config_path.read_text()) or {}
    hosts_section = raw.setdefault("hosts", {})
    if isinstance(hosts_section, list):
        # bare list format — normalise to dict form
        hosts_section = {"addresses": hosts_section}
        raw["hosts"] = hosts_section
    existing: List[str] = hosts_section.setdefault("addresses", [])
    existing_set = set(existing)

    added = skipped = errors = 0
    for lineno, raw_line in enumerate(file.read_text().splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        target = line.split(None, 1)[0].strip(",;")

        try:
            expand_target(target)  # validate only
        except ValueError as e:
            click.echo(f"  line {lineno}: skipping {target!r} — {e}", err=True)
            errors += 1
            continue

        if target in existing_set:
            skipped += 1
            continue

        existing.append(target)
        existing_set.add(target)
        added += 1

    config_path.write_text(yaml.dump(raw, default_flow_style=False, allow_unicode=True))
    click.echo(f"Imported {added} host(s), skipped {skipped} duplicate(s), {errors} error(s).")
    if added:
        click.echo("Restart the service to apply: sudo systemctl restart netwatchdog")


# ---- dedupe-hosts ----------------------------------------------------------

@cli.command("dedupe-hosts")
@click.pass_context
def dedupe_hosts(ctx: click.Context) -> None:
    """Remove duplicate addresses from the config file."""
    import yaml

    config_path = ctx.obj.get("config_path")
    if config_path is None:
        raise click.ClickException(
            "No config file specified. Use: netwatchdog --config /path/to/config.yaml dedupe-hosts"
        )

    raw = yaml.safe_load(config_path.read_text()) or {}
    hosts_section = raw.get("hosts", {})
    if isinstance(hosts_section, list):
        addresses = hosts_section
    else:
        addresses = hosts_section.get("addresses", [])

    before = len(addresses)
    seen: set = set()
    deduped = []
    for addr in addresses:
        if addr not in seen:
            seen.add(addr)
            deduped.append(addr)

    removed = before - len(deduped)

    if isinstance(raw.get("hosts"), list):
        raw["hosts"] = deduped
    else:
        raw["hosts"]["addresses"] = deduped

    config_path.write_text(yaml.dump(raw, default_flow_style=False, allow_unicode=True))
    click.echo(f"Removed {removed} duplicate(s), {len(deduped)} unique address(es) remain.")
    if removed:
        click.echo("Restart the service to apply: sudo systemctl restart netwatchdog")

@cli.command("remove-host")
@click.argument("target")
@click.pass_context
def remove_host(ctx: click.Context, target: str) -> None:
    """Remove host(s) from monitoring. Accepts single IP, CIDR, or dash range."""
    cfg, engine, session = _get_session(ctx)

    try:
        ips = expand_target(target)
    except ValueError as e:
        raise click.ClickException(str(e))

    removed = 0
    config_skipped = 0
    for ip in ips:
        host = session.query(Host).filter_by(ip_address=ip).first()
        if host:
            if host.source == "config":
                config_skipped += 1
                continue
            session.delete(host)
            removed += 1

    session.commit()
    session.close()
    msg = f"Removed {removed} host(s)."
    if config_skipped:
        msg += f" Skipped {config_skipped} config-defined host(s) (remove from YAML instead)."
    click.echo(msg)


# ---- list-hosts ------------------------------------------------------------

@cli.command("list-hosts")
@click.option("--all", "-a", "show_all", is_flag=True, help="Include inactive hosts.")
@click.pass_context
def list_hosts(ctx: click.Context, show_all: bool) -> None:
    """List monitored hosts."""
    cfg, engine, session = _get_session(ctx)

    query = session.query(Host)
    if not show_all:
        query = query.filter_by(active=1)
    hosts = query.order_by(Host.ip_address).all()

    if not hosts:
        click.echo("No hosts configured.")
        session.close()
        return

    click.echo(f"{'IP Address':<20} {'Label':<25} {'Source':<10} {'Active':<8} {'Added'}")
    click.echo("-" * 85)
    for h in hosts:
        active_str = "yes" if h.active else "no"
        label = h.label or ""
        source = h.source or "cli"
        click.echo(f"{h.ip_address:<20} {label:<25} {source:<10} {active_str:<8} {h.created_at}")

    click.echo(f"\nTotal: {len(hosts)} host(s)")
    session.close()


# ---- status ----------------------------------------------------------------

@cli.command("status")
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show summary of current monitoring state."""
    cfg, engine, session = _get_session(ctx)

    total_hosts = session.query(Host).filter_by(active=1).count()
    from netwatchdog.database.models import ScanJob, PortState, ChangeEvent

    open_ports = session.query(PortState).filter_by(state="open").count()
    last_job = (
        session.query(ScanJob)
        .filter_by(status="completed")
        .order_by(ScanJob.completed_at.desc())
        .first()
    )

    click.echo(f"Active hosts:    {total_hosts}")
    click.echo(f"Open ports:      {open_ports}")
    if last_job:
        click.echo(f"Last scan:       {last_job.scan_type} at {last_job.completed_at}")
    else:
        click.echo("Last scan:       none")
    session.close()


# ---- scan ------------------------------------------------------------------

@cli.command("scan")
@click.option("--type", "-t", "scan_type", type=click.Choice(["quick", "full"]), default="quick")
@click.pass_context
def scan_now(ctx: click.Context, scan_type: str) -> None:
    """Run a scan immediately."""
    cfg = load_config(ctx.obj.get("config_path"))
    engine = create_db_engine(cfg.database.path, wal_mode=cfg.database.wal_mode)
    run_migrations(engine)

    # Sync hosts from config
    if cfg.hosts:
        factory = create_session_factory(engine)
        session = factory()
        sync_hosts_from_config(session, cfg)
        session.close()

    # Build notifiers
    notifiers = _build_notifiers(cfg)

    from netwatchdog.scheduler.jobs import run_scan_job
    click.echo(f"Starting {scan_type} scan...")
    job = run_scan_job(engine, cfg, scan_type, triggered_by="manual", notifiers=notifiers)
    click.echo(f"Scan complete: status={job.status}, hosts={job.hosts_scanned}")
    if job.error_message:
        click.echo(f"Errors: {job.error_message}")


# ---- start -----------------------------------------------------------------

@cli.command("start")
@click.pass_context
def start(ctx: click.Context) -> None:
    """Start the scheduler (runs scans on configured schedule)."""
    cfg = load_config(ctx.obj.get("config_path"))
    engine = create_db_engine(cfg.database.path, wal_mode=cfg.database.wal_mode)
    run_migrations(engine)

    # Sync hosts from config
    if cfg.hosts:
        factory = create_session_factory(engine)
        session = factory()
        counts = sync_hosts_from_config(session, cfg)
        session.close()
        click.echo(
            f"Config hosts: {counts['added']} added, "
            f"{counts['updated']} updated, "
            f"{counts['unchanged']} unchanged."
        )

    notifiers = _build_notifiers(cfg)

    from netwatchdog.scheduler.manager import SchedulerManager
    manager = SchedulerManager(engine, cfg, notifiers)

    click.echo("Starting scheduler...")
    click.echo(f"  Quick scan: {'enabled' if cfg.schedule.quick_scan.enabled else 'disabled'}"
               f" ({cfg.schedule.quick_scan.cron})")
    click.echo(f"  Full scan:  {'enabled' if cfg.schedule.full_scan.enabled else 'disabled'}"
               f" ({cfg.schedule.full_scan.cron})")
    click.echo("Press Ctrl+C to stop.")

    manager.start()


# ---- helpers ---------------------------------------------------------------

def _build_notifiers(cfg) -> list:
    """Build notifier instances from config."""
    notifiers = []
    if cfg.notifications.log.enabled:
        from netwatchdog.notifier.log_notifier import LogNotifier
        notifiers.append(LogNotifier(
            log_path=cfg.notifications.log.path,
            rotate_mb=cfg.notifications.log.rotate_mb,
            backup_count=cfg.notifications.log.backup_count,
        ))
    if cfg.notifications.email.enabled:
        from netwatchdog.notifier.email_notifier import EmailNotifier
        notifiers.append(EmailNotifier(cfg.notifications.email))
    return notifiers
