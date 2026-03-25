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


# ---- remove-host -----------------------------------------------------------

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
