# netwatchdog

Network port change monitoring system. Periodically scans IP addresses for open TCP ports and alerts on any changes.

## Features

- Scans IP addresses using nmap and/or masscan
- Daily quick scans (well-known ports) and weekly full scans (all 65535 ports)
- Detects changes: open, closed, filtered, unfiltered
- Notifies via log file and email
- Web UI dashboard with history and change log

## Requirements

- Linux
- Python 3.8+
- nmap
- masscan (optional, recommended for full scans)

## Installation

```bash
git clone --branch claude/deployment-readiness-check-atHl6 https://github.com/krudolf55/netwatchdog.git
cd netwatchdog
sudo bash deploy/install.sh
```

Then edit the config before starting:

```bash
sudo nano /etc/netwatchdog/netwatchdog.yaml
```

## Managing Hosts

**Add a single host, CIDR range, or dash range:**

```bash
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml add-host 192.168.1.1
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml add-host 192.168.1.0/24
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml add-host 10.0.0.1-10.0.0.50
```

**Import hosts from a text file (one address per line):**

```bash
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml import-hosts /path/to/ips.txt
```

The file can contain single IPs, CIDR ranges, or dash ranges. Blank lines and lines starting with `#` are ignored. Trailing commas are stripped automatically. After importing, restart the service to apply:

```bash
sudo systemctl restart netwatchdog
```

**List all hosts that will be scanned:**

```bash
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml list-hosts
```

**Remove a host:**

```bash
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml remove-host 192.168.1.1
```

**Reset the database (reload all hosts from config):**

If the database gets out of sync or you want a clean slate, delete it and restart. The service will rebuild it from the config file automatically:

```bash
sudo systemctl stop netwatchdog
sudo rm /var/lib/netwatchdog/netwatchdog.db
sudo systemctl start netwatchdog
```

All hosts defined in `/etc/netwatchdog/netwatchdog.yaml` will be reloaded. Scan history and change logs will be lost.

## Service Management

```bash
sudo systemctl start netwatchdog
sudo systemctl stop netwatchdog
sudo systemctl restart netwatchdog
sudo systemctl status netwatchdog
journalctl -u netwatchdog -f
```

## Running a Scan Immediately

```bash
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml scan --type quick
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml scan --type full
```

Scan a single host:

```bash
netwatchdog --config /etc/netwatchdog/netwatchdog.yaml scan --host 192.168.1.1
```

## Scan Output

Port changes are appended to the change log as they are detected:

```bash
tail -f /var/log/netwatchdog/changes.jsonl
```

General scan progress and errors:

```bash
tail -f /var/log/netwatchdog/netwatchdog.log
```

Query the database directly:

```bash
# open ports found
sqlite3 /var/lib/netwatchdog/netwatchdog.db "SELECT h.ip_address, p.port, p.protocol, p.service_name FROM port_states p JOIN hosts h ON h.id = p.host_id WHERE p.state='open' ORDER BY h.ip_address, p.port;"

# recent scan jobs
sqlite3 /var/lib/netwatchdog/netwatchdog.db "SELECT id, scan_type, status, hosts_scanned, started_at, completed_at FROM scan_jobs ORDER BY started_at DESC LIMIT 10;"

# recent changes detected
sqlite3 /var/lib/netwatchdog/netwatchdog.db "SELECT h.ip_address, c.port, c.change_type, c.detected_at FROM change_events c JOIN hosts h ON h.id = c.host_id ORDER BY c.detected_at DESC LIMIT 20;"
```

## Configuration

The config file lives at `/etc/netwatchdog/netwatchdog.yaml`. An annotated example is at `config/netwatchdog.example.yaml`.

Key settings to review before deploying:

- `web.secret_key` — set to a random string
- `hosts.addresses` — list of IPs/ranges to scan
- `schedule` — cron expressions for quick and full scans
- `notifications` — email alerting

## Development

```bash
pip install -e ".[dev]"
pre-commit install
pytest
```
