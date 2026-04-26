# periscan

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

## Quick Setup

**1. Clone and install**

```bash
git clone https://github.com/krudolf55/periscan.git
cd periscan
sudo bash deploy/install.sh
```

**2. Create your config file**

```bash
sudo mkdir -p /etc/periscan
sudo cp config/periscan.example.yaml /etc/periscan/periscan.yaml
sudo nano /etc/periscan/periscan.yaml
```

Set at minimum:
- `web.secret_key` — change from `changeme`
- `hosts.addresses` — add your IP ranges (or use `import-hosts` below)

**3. Import your hosts (if you have a list)**

```bash
sudo periscan -c /etc/periscan/periscan.yaml import-hosts /path/to/hosts.txt
```

**4. Start the service**

```bash
sudo systemctl enable --now periscan
sudo systemctl status periscan
```

**5. Verify it's running**

```bash
sudo journalctl -u periscan -f
```

## Managing Hosts

**Add a single host, CIDR range, or dash range:**

```bash
periscan --config /etc/periscan/periscan.yaml add-host 192.168.1.1
periscan --config /etc/periscan/periscan.yaml add-host 192.168.1.0/24
periscan --config /etc/periscan/periscan.yaml add-host 10.0.0.1-10.0.0.50
```

**Edit the config file directly:**

```bash
sudo nano /etc/periscan/periscan.yaml
```

Add entries under `hosts.addresses`, then restart the service to sync them into the database:

```bash
sudo systemctl restart periscan
```

**Import hosts from a text file (one address per line):**

```bash
periscan --config /etc/periscan/periscan.yaml import-hosts /path/to/ips.txt
```

The file can contain single IPs, CIDR ranges, or dash ranges. Blank lines and lines starting with `#` are ignored. Trailing commas are stripped automatically. After importing, restart the service to apply:

```bash
sudo systemctl restart periscan
```

**List all hosts that will be scanned:**

```bash
periscan --config /etc/periscan/periscan.yaml list-hosts
```

**Remove a host:**

```bash
periscan --config /etc/periscan/periscan.yaml remove-host 192.168.1.1
```

**Reset the database (reload all hosts from config):**

If the database gets out of sync or you want a clean slate, delete it and restart. The service will rebuild it from the config file automatically:

```bash
sudo systemctl stop periscan
sudo rm /var/lib/periscan/periscan.db
sudo systemctl start periscan
```

All hosts defined in `/etc/periscan/periscan.yaml` will be reloaded. Scan history and change logs will be lost.

## Service Management

```bash
sudo systemctl start periscan
sudo systemctl stop periscan
sudo systemctl restart periscan
sudo systemctl status periscan
journalctl -u periscan -f
```

## Running a Scan Immediately

```bash
periscan --config /etc/periscan/periscan.yaml scan --type quick
periscan --config /etc/periscan/periscan.yaml scan --type full
```

Scan a single host:

```bash
periscan --config /etc/periscan/periscan.yaml scan --host 192.168.1.1
```

## Scan Output

Port changes are appended to the change log as they are detected:

```bash
tail -f /var/log/periscan/changes.jsonl
```

General scan progress and errors:

```bash
tail -f /var/log/periscan/periscan.log
```

Query the database directly:

```bash
# open ports found
sqlite3 /var/lib/periscan/periscan.db "SELECT h.ip_address, p.port, p.protocol, p.service_name FROM port_states p JOIN hosts h ON h.id = p.host_id WHERE p.state='open' ORDER BY h.ip_address, p.port;"

# recent scan jobs
sqlite3 /var/lib/periscan/periscan.db "SELECT id, scan_type, status, hosts_scanned, started_at, completed_at FROM scan_jobs ORDER BY started_at DESC LIMIT 10;"

# recent changes detected
sqlite3 /var/lib/periscan/periscan.db "SELECT h.ip_address, c.port, c.previous_state, c.current_state, c.detected_at FROM change_events c JOIN hosts h ON h.id = c.host_id ORDER BY c.detected_at DESC LIMIT 20;"
```

## Configuration

The config file lives at `/etc/periscan/periscan.yaml`. An annotated example is at `config/periscan.example.yaml`.

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
