# 🛡️ Mini SIEM - Security Information & Event Management System

A lightweight, real-time Security Information and Event Management (SIEM) system
built entirely in Python using the standard library (no pip installs required).

## Features

- **Log Ingestion** - Parses SSH (`auth.log`) and system (`syslog`) log files
- **Real-Time File Watching** - Tails log files live with inode-safe rotation detection
- **Rule-Based Detection** - Fires alerts for 5 threat patterns automatically
- **IP Geolocation** - Enriches attacker IPs with country/city/org data (cached in SQLite)
- **SQLite Storage** - Persists all events, alerts, and geo lookups locally
- **Web Dashboard** - Live browser UI with auto-refresh, alert feed, charts, and event log

## Quick Start

```bash
# No installation needed — Python 3.13+ standard library only
python siem.py
# Open http://localhost:8080
```

Click **"Load Sample Logs"** on the dashboard to populate demo data instantly.

## Project Structure

```
mini_siem/
├── siem.py          # Main application (ingestion, detection, HTTP server)
└── dashboard.html   # Frontend dashboard (auto-loaded by siem.py)
```

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `BRUTE_FORCE_DETECTED` | 5+ SSH failures from same IP | CRITICAL |
| `SUCCESS_AFTER_FAILURES` | Login succeeded after prior failures | HIGH |
| `ROOT_LOGIN_ATTEMPT` | Any root login attempt | HIGH |
| `PORT_SCAN_DETECTED` | 3+ invalid user probes from same IP | HIGH |
| `NEW_USER_CREATED` | New system account created | MEDIUM |

## Monitoring Real Log Files

Uncomment these lines in `main()` inside `siem.py`:

```python
watch_paths = ["/var/log/auth.log", "/var/log/syslog"]
watcher = LogFileWatcher(watch_paths, db_path=DB, poll_interval=1.0)
watcher.start()
SIEMHandler.watcher = watcher
```

> **Note:** Reading `/var/log/auth.log` may require `sudo` on Linux.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard UI |
| `GET /api/stats` | JSON — all stats, events, alerts |
| `GET /api/ingest_sample` | Load sample log data |
| `GET /api/clear` | Clear all data |
| `GET /api/watcher_status` | Show watched files |

## Tech Stack

- **Python 3.13+** — `http.server`, `sqlite3`, `threading`, `urllib`, `re`
- **SQLite** — embedded database, zero config
- **HTML/CSS/JS** — single-file dashboard, no frameworks
- **ip-api.com** — free IP geolocation (no API key required)

## Skills Demonstrated

- Log parsing with regex pattern matching
- Threat detection with rule-based correlation
- Real-time file monitoring with inode-safe rotation handling
- Concurrent IP enrichment using Python threads
- REST API design with Python's built-in HTTP server
- Persistent storage with SQLite
- Frontend dashboard design

## License

MIT — free to use, modify, and include in your portfolio.
