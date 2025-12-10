# Web Intrusion Detection & Response

Log-based **Web Intrusion Detection & Response** system written in Python.

The project monitors web and database logs in real time, detects suspicious activity (SQL injection, XSS, HTTP flood / brute force, scanners, PostgreSQL auth failures), and can:

* generate structured incident reports (JSON),
* send alerts (SMTP, webhook),
* trigger automated response (iptables, Fail2Ban).

It is designed as a **lightweight, modular IDS** that fits well in a lab / homelab / blue-team environment and can be integrated with other tools (SIEM, dashboards, etc.).

---

## Overview

The IDS:

* tails one or more log files (Apache, database logs, system logs…),
* parses or wraps each line into a normalized `event` (Python dict),
* runs several detectors on each event (loaded dynamically from `src/detectors/`),
* when an incident is raised, it:

  * logs it,
  * writes a JSON report under `reports/incidents/`,
  * optionally sends alerts (email / webhook),
  * optionally blocks the source IP (iptables / Fail2Ban), depending on severity.

All behaviour is driven by a YAML configuration file: `config/config.yml`.

---

## Main features

### 🔎 Log monitoring

* Real-time “tail” of configured log files.
* Apache access logs are parsed into structured fields:

  * IP, timestamp, method, path, status, size, referrer, user-agent…
* Other logs (e.g. MySQL, PostgreSQL, app logs) are handled as raw lines but wrapped into events with:

  * `source` (inferred from path),
  * `timestamp`,
  * `raw` log line.
* Log files to monitor are discovered using:

  * `logs.include_globs`
  * `logs.exclude_globs`
    in `config.yml`.

### 🛡 Detection

Detectors live under `src/detectors/` and are loaded dynamically.

Current detectors include:

#### 1. SQL Injection (`sqli.py`)

Inspects web requests (from Apache logs) and looks for SQLi patterns such as:

* encoded quotes (`%27`),
* `UNION SELECT`,
* references to `information_schema`,
* time-based payloads (`sleep(`, `benchmark(`),
* `sqlmap` fingerprints in user-agent / payloads.

Severity is adjusted:

* generic SQLi patterns → typically `HIGH`,
* explicit `sqlmap` usage → escalated to `CRITICAL`.

#### 2. XSS (`xss.py`)

Searches for XSS indicators in the log line and HTTP path, for example:

* `<script`, `</script`,
* `javascript:`,
* `onerror=`, `onload=`,
* `<img`, `<svg`, `<iframe`,
* `alert(`, etc.

Severity is based on how strong the pattern is (e.g. `<script` / `javascript:` is considered more severe).

#### 3. HTTP flood / brute force (`brute_force.py`)

Tracks requests per IP over a sliding time window.

Configuration example:

```yaml
detection:
  brute_force:
    enabled: true
    requests_threshold: 20
    window_seconds: 2
```

If an IP sends more than `requests_threshold` requests in `window_seconds`, an incident is raised (e.g. potential HTTP flood / aggressive brute force).

#### 4. Scanner fingerprints (`scanner.py`)

Looks for known security tools in user-agent or log content, for example:

* Nikto
* sqlmap
* Acunetix
* Nessus / OpenVAS
* WPScan
* Nmap-style probes

These events are marked with higher severity, since they usually indicate active reconnaissance.

#### 5. PostgreSQL auth failures (`postgresql.py`)

Watches PostgreSQL logs for typical authentication failure messages.

Useful to spot:

* brute-force attempts,
* or repeated misconfigurations on database access.

---

## Alerting & response

When a detector returns an incident, `handle_incident()` in `src/main.py` takes over.

For each incident, the code:

1. logs it (console + `logs/ids.log`),
2. writes a JSON report under `reports/incidents/`,
3. sends alerts if severity is high enough,
4. blocks the IP if severity reaches the blocking threshold.

Thresholds are configurable in `config.yml`:

```yaml
reporting:
  incidents_dir: "./reports/incidents"
  severity_min_email: "MEDIUM"
  severity_min_block: "HIGH"
```

### 📧 SMTP alerts

Configured in `config/config.yml`:

```yaml
alerting:
  smtp:
    enabled: true
    server: "smtp.gmail.com"
    port: 587
    from_email: "ids@example.com"
    to_email: "soc@example.com"
    username_env: "IDS_SMTP_USER"
    password_env: "IDS_SMTP_PASSWORD"
```

Credentials are not stored in the repo:
they are read from environment variables (`IDS_SMTP_USER`, `IDS_SMTP_PASSWORD`).

The alerter also avoids sending the exact same body twice in a row to reduce noise.

### 🌐 Webhook alerts

A generic HTTP POST (JSON) to any endpoint:

```yaml
alerting:
  webhook:
    enabled: true
    url: "https://example.com/webhook"
    timeout_seconds: 5
    verify_tls: true
```

The payload contains a title, a message, and optional extra fields (attack type, severity, IP, report path, etc.).

### ⛔ Automated response (iptables & Fail2Ban)

Network-level reaction is handled by:

```yaml
response:
  iptables:
    enabled: true
    command: "sudo iptables -A INPUT -s {ip} -j DROP"

  fail2ban:
    enabled: false
    jail: "apache-auth"
    command: "sudo fail2ban-client set {jail} banip {ip}"
```

* `IptablesResponder` runs the configured command and keeps an in-memory set of already blocked IPs.
* `Fail2BanResponder` integrates with `fail2ban-client` for setups that already use Fail2Ban and existing jails.

---

## Incident reporting

Every incident is saved as a JSON file in `reports/incidents/`, with a filename like:

```text
reports/incidents/20251210T101139Z_SQL_Injection.json
```

Each report contains:

* `attack_type`
* `description`
* `severity`
* `ip`
* `event` (normalized data + raw log line)

Timestamps are stored in ISO format, which is convenient if you later import these JSON files into a SIEM or build dashboards.

---

## Architecture (high level)

```text
       Log files (Apache, DB, system)
                     │
                     ▼
        +---------------------------+
        |     log_watcher.py        |
        |  - discovers sources      |
        |  - tails files            |
        |  - parses Apache          |
        +---------------------------+
                     │
         normalized events (dict)
                     │
                     ▼
        +---------------------------+
        |        detectors/         |
        |  - SQLi, XSS, scanners,   |
        |    brute force, Postgres  |
        +---------------------------+
                     │
               incidents (dict)
                     │
                     ▼
        +---------------------------+
        |      main.handle_incident |
        |  - logging                |
        |  - JSON report            |
        |  - SMTP / webhook         |
        |  - iptables / Fail2Ban    |
        +---------------------------+
```

Configuration, thresholds and paths are handled by `src/config.py` and `config/config.yml`.

---

## Getting started

### 1. Clone the repository

```bash
git clone https://github.com/TFLR/web-intrusion-detection-and-response.git
cd web-intrusion-detection-and-response
```

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Adjust `config/config.yml`

At least:

* review the `logs.include_globs` / `exclude_globs`,
* decide which responses you want to enable:

  * logging + JSON only,
  * email / webhook,
  * iptables / Fail2Ban,
* tune brute-force thresholds and severity thresholds if needed.

### 5. Run the IDS manually

```bash
python3 -m src.main
```

The program will start tailing log files, run detectors on each new event, and create incidents / alerts according to your configuration.

---

## Running as a systemd service (Linux)

You can run the IDS as a **Linux service** so it starts automatically and runs in the background.

> ⚠️ Note: blocking IPs with iptables / interacting with Fail2Ban usually requires root privileges or appropriate sudo rules. In a lab/homelab setup, running the service as root is the simplest option, but you can also create a dedicated user and sudo rules if you prefer.

### 1. Choose a directory

For example:

```bash
sudo mkdir -p /opt/web-ids
sudo chown -R $(whoami):$(whoami) /opt/web-ids

cd /opt/web-ids
git clone https://github.com/TFLR/web-intrusion-detection-and-response.git .
```

Then create and activate a virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Make sure your `config/config.yml` is correctly set for this machine.

### 2. (Optional) Set environment variables

If you use SMTP with credentials, you can store them in an env file, for example:

```bash
sudo nano /etc/web-ids.env
```

With content such as:

```bash
IDS_SMTP_USER="your_smtp_username"
IDS_SMTP_PASSWORD="your_smtp_password"
```

Save and restrict permissions:

```bash
sudo chmod 600 /etc/web-ids.env
```

### 3. Create a systemd unit

Create the file:

```bash
sudo nano /etc/systemd/system/web-ids.service
```

Example unit file:

```ini
[Unit]
Description=Web Intrusion Detection & Response
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/web-ids
ExecStart=/opt/web-ids/.venv/bin/python -m src.main
Restart=on-failure

# Run as root for iptables/Fail2Ban, or change to a dedicated user if you prefer
User=root
Group=root

# Load SMTP credentials (optional)
EnvironmentFile=-/etc/web-ids.env

# Make sure Python sees the correct encoding and locale if needed
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Adapt paths if your repo or venv is elsewhere.

### 4. Reload systemd and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl start web-ids.service
sudo systemctl status web-ids.service
```

If everything looks good, enable it on boot:

```bash
sudo systemctl enable web-ids.service
```

### 5. Check logs

You can check service logs via `journalctl`:

```bash
sudo journalctl -u web-ids.service -f
```

And you still have the internal IDS log file in the repo directory:

```bash
tail -f logs/ids.log
```

---

## Scope and next steps

The project focuses on:

* log-based detection for web and database services,
* modular detectors written in Python,
* simple but usable alerting and automated response.

Possible evolutions:

* dedicated Nginx parsing,
* additional detectors (LFI/RFI, path traversal, auth anomalies, CMS attacks),
* direct export to a SIEM (HTTP API, syslog, etc.),
* automated tests around detectors and log parsing.
