# netwatchdog

Network port change monitoring system. Periodically scans IP addresses for open TCP ports and alerts on any changes.

## Features

- Scans 1–1000 IP addresses using nmap and/or masscan
- Daily quick scans (well-known ports) and configurable full scans (all 65535 ports)
- Detects changes: open, closed, filtered, unfiltered
- Notifies via log file and email
- Web UI dashboard with history and change log

## Requirements

- Linux
- Python 3.11+
- nmap
- masscan (optional, recommended for full scans)

## Quick Start

```bash
pip install -e .
netwatchdog init-db
netwatchdog add-host 192.168.1.0/24
netwatchdog start
```

Web UI available at `http://localhost:8080`.

## Configuration

Copy `config/netwatchdog.example.yaml` to `config/netwatchdog.yaml` and edit to suit your environment.

See [docs/configuration.md](docs/configuration.md) for full reference.

## Development

```bash
pip install -e ".[dev]"
pre-commit install
pytest
```
