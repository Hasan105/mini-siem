"""
Mini SIEM — Security Information & Event Management System
Features: Log ingestion, real-time file watching, rule-based detection,
          IP geolocation, SQLite storage, web dashboard
Author: Built with Python 3.13+ standard library only
"""

import sqlite3
import re
import os
import json
import threading
import time
import urllib.request
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse


# ─── Database Setup ────────────────────────────────────────────────────────────

def init_db(db_path="siem.db"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            source_file TEXT,
            log_line   TEXT,
            event_type TEXT,
            severity   TEXT,
            ip_address TEXT,
            username   TEXT,
            message    TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            rule_name  TEXT,
            severity   TEXT,
            ip_address TEXT,
            username   TEXT,
            detail     TEXT,
            count      INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip        TEXT PRIMARY KEY,
            country   TEXT,
            city      TEXT,
            org       TEXT,
            cached_at TEXT
        )
    """)
    conn.commit()
    conn.close()


# ─── IP Geolocation ────────────────────────────────────────────────────────────

def is_private_ip(ip):
    private_prefixes = (
        "10.", "192.168.", "127.", "0.", "169.254.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    )
    return any(ip.startswith(p) for p in private_prefixes)


def geolocate_ip(ip, db_path="siem.db"):
    """Look up IP geolocation using ip-api.com (free, no API key).
    Results are cached in SQLite to avoid redundant requests."""
    if not ip or is_private_ip(ip):
        return {"country": "Private/LAN", "city": "", "org": ""}

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT country, city, org FROM geo_cache WHERE ip=?", (ip,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"country": row[0], "city": row[1], "org": row[2]}

    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,city,org,status"
        req = urllib.request.Request(url, headers={"User-Agent": "MiniSIEM/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {"country": data.get("country", "Unknown"),
                      "city":    data.get("city", ""),
                      "org":     data.get("org", "")}
        else:
            result = {"country": "Unknown", "city": "", "org": ""}
    except Exception:
        result = {"country": "Lookup failed", "city": "", "org": ""}

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT OR REPLACE INTO geo_cache (ip,country,city,org,cached_at) VALUES (?,?,?,?,?)",
        (ip, result["country"], result["city"], result["org"], datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return result


def geolocate_batch(ips, db_path="siem.db"):
    """Geolocate multiple IPs concurrently using threads."""
    results = {}
    unique  = list(set(ip for ip in ips if ip))

    def worker(ip):
        results[ip] = geolocate_ip(ip, db_path)

    threads = [threading.Thread(target=worker, args=(ip,), daemon=True) for ip in unique]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5)
    return results


# ─── Log Parsers ───────────────────────────────────────────────────────────────

SSH_PATTERNS = [
    (r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", "SSH_FAIL",         "MEDIUM"),
    (r"Accepted password for (\S+) from ([\d.]+)",                  "SSH_SUCCESS",      "LOW"),
    (r"Accepted publickey for (\S+) from ([\d.]+)",                 "SSH_KEY_LOGIN",    "LOW"),
    (r"Invalid user (\S+) from ([\d.]+)",                           "SSH_INVALID_USER", "MEDIUM"),
    (r"ROOT LOGIN.*from ([\d.]+)",                                  "ROOT_LOGIN",       "HIGH"),
    (r"Connection closed by ([\d.]+)",                              "SSH_DISCONNECT",   "INFO"),
    (r"maximum authentication attempts exceeded.*from ([\d.]+)",    "SSH_BRUTE_FORCE",  "HIGH"),
    (r"Did not receive identification string from ([\d.]+)",        "SSH_SCAN",         "MEDIUM"),
]

SYSLOG_PATTERNS = [
    (r"sudo:\s+(\S+).*COMMAND=(.*)",        "SUDO_COMMAND", "MEDIUM"),
    (r"useradd.*name=(\S+)",                "USER_CREATED", "HIGH"),
    (r"userdel.*name=(\S+)",                "USER_DELETED", "HIGH"),
    (r"OUT OF MEMORY|oom.killer",           "OOM_KILL",     "HIGH"),
    (r"segfault",                           "SEGFAULT",     "MEDIUM"),
    (r"authentication failure.*user=(\S+)", "AUTH_FAILURE", "MEDIUM"),
]


def parse_line(line, source_file):
    line = line.strip()
    if not line:
        return None

    patterns = (
        SSH_PATTERNS
        if any(k in source_file.lower() for k in ("auth", "ssh", "secure"))
        else SYSLOG_PATTERNS
    )

    timestamp = datetime.now().isoformat()
    ts_match  = re.match(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
    if ts_match:
        timestamp = ts_match.group(1)

    for pattern, event_type, severity in patterns:
        m = re.search(pattern, line, re.IGNORECASE)
        if m:
            groups   = m.groups()
            username = groups[0] if len(groups) >= 1 else ""
            ip       = groups[1] if len(groups) >= 2 else ""
            if event_type == "ROOT_LOGIN":
                ip, username = groups[0], "root"
            return {
                "timestamp":   timestamp,
                "source_file": source_file,
                "log_line":    line[:300],
                "event_type":  event_type,
                "severity":    severity,
                "ip_address":  ip,
                "username":    username,
                "message":     f"{event_type} detected",
            }
    return None


# ─── Log Ingestion ─────────────────────────────────────────────────────────────

def ingest_lines(lines, source_file, db_path="siem.db"):
    conn  = sqlite3.connect(db_path)
    c     = conn.cursor()
    count = 0
    for line in lines:
        parsed = parse_line(line, source_file)
        if parsed:
            c.execute("""
                INSERT INTO events
                (timestamp,source_file,log_line,event_type,severity,ip_address,username,message)
                VALUES (?,?,?,?,?,?,?,?)
            """, (parsed["timestamp"], parsed["source_file"], parsed["log_line"],
                  parsed["event_type"], parsed["severity"],   parsed["ip_address"],
                  parsed["username"],  parsed["message"]))
            count += 1
    conn.commit()
    conn.close()
    return count


def ingest_log_file(filepath, db_path="siem.db"):
    if not os.path.exists(filepath):
        return 0
    with open(filepath, "r", errors="ignore") as f:
        return ingest_lines(f.readlines(), filepath, db_path)


def ingest_sample_logs(db_path="siem.db"):
    sample = [
        "Jan 15 10:01:01 server sshd[1234]: Failed password for root from 192.168.1.105 port 22",
        "Jan 15 10:01:03 server sshd[1234]: Failed password for root from 192.168.1.105 port 22",
        "Jan 15 10:01:05 server sshd[1234]: Failed password for root from 192.168.1.105 port 22",
        "Jan 15 10:01:07 server sshd[1234]: Failed password for root from 192.168.1.105 port 22",
        "Jan 15 10:01:09 server sshd[1234]: Failed password for root from 192.168.1.105 port 22",
        "Jan 15 10:01:11 server sshd[1234]: Failed password for root from 192.168.1.105 port 22",
        "Jan 15 10:02:00 server sshd[1234]: Accepted password for admin from 10.0.0.15 port 22",
        "Jan 15 10:03:00 server sshd[1235]: Invalid user hacker from 203.0.113.42 port 22",
        "Jan 15 10:04:00 server sshd[1236]: Failed password for invalid user test from 198.51.100.7 port 22",
        "Jan 15 10:05:00 server sudo: alice : COMMAND=/bin/bash",
        "Jan 15 10:06:00 server useradd[999]: new user; name=backdoor",
        "Jan 15 10:07:00 server sshd[1237]: ROOT LOGIN REFUSED FROM 172.16.0.99",
        "Jan 15 10:08:00 server sshd[1238]: Failed password for bob from 192.168.1.105 port 22",
        "Jan 15 10:09:00 server kernel: Out of memory: Kill process 1234",
        "Jan 15 10:10:00 server sshd[1239]: Accepted password for deploy from 10.0.0.20 port 22",
        "Jan 15 10:11:00 server sshd[1240]: Failed password for admin from 45.33.32.156 port 22",
        "Jan 15 10:11:02 server sshd[1240]: Failed password for admin from 45.33.32.156 port 22",
        "Jan 15 10:11:04 server sshd[1240]: Failed password for admin from 45.33.32.156 port 22",
        "Jan 15 10:12:00 server sshd[1241]: Did not receive identification string from 185.220.101.5",
        "Jan 15 10:13:00 server sshd[1242]: Accepted publickey for devuser from 10.0.0.50 port 22",
    ]
    return ingest_lines(sample, "auth.log", db_path)


# ─── Real-Time File Watcher ────────────────────────────────────────────────────

class LogFileWatcher:
    """
    Watches log files for new lines using inode-safe tail logic.
    Handles log rotation automatically. Runs as a daemon thread.
    No third-party libraries required.
    """

    def __init__(self, paths, db_path="siem.db", poll_interval=1.0):
        self._paths       = paths
        self._db_path     = db_path
        self._interval    = poll_interval
        self._offsets     = {}
        self._inodes      = {}
        self._stop_event  = threading.Event()
        self._thread      = threading.Thread(target=self._run, daemon=True)

    def start(self):
        for path in self._paths:
            if os.path.exists(path):
                stat = os.stat(path)
                self._offsets[path] = stat.st_size   # start from current end
                self._inodes[path]  = stat.st_ino
        self._thread.start()
        print(f"[watcher] Monitoring {len(self._paths)} file(s) for new events...")

    def stop(self):
        self._stop_event.set()
        self._thread.join(timeout=3)

    def _run(self):
        while not self._stop_event.is_set():
            for path in self._paths:
                self._check(path)
            time.sleep(self._interval)

    def _check(self, path):
        if not os.path.exists(path):
            return
        try:
            stat  = os.stat(path)
            inode = stat.st_ino
            size  = stat.st_size

            # Detect log rotation (new inode or file shrank)
            if self._inodes.get(path) != inode or size < self._offsets.get(path, 0):
                print(f"[watcher] Log rotation detected: {path}")
                self._offsets[path] = 0
                self._inodes[path]  = inode

            if size <= self._offsets.get(path, 0):
                return

            with open(path, "r", errors="ignore") as f:
                f.seek(self._offsets.get(path, 0))
                new_lines = f.readlines()
                self._offsets[path] = f.tell()

            count = ingest_lines(new_lines, path, self._db_path)
            if count:
                run_detection_rules(self._db_path)
                print(f"[watcher] +{count} event(s) from {os.path.basename(path)}")

        except OSError:
            pass


# ─── Detection Rules ───────────────────────────────────────────────────────────

def run_detection_rules(db_path="siem.db"):
    conn   = sqlite3.connect(db_path)
    c      = conn.cursor()
    alerts = []

    # Rule 1: SSH Brute Force
    c.execute("""
        SELECT ip_address, COUNT(*) as cnt FROM events
        WHERE event_type='SSH_FAIL' AND ip_address != ''
        GROUP BY ip_address HAVING cnt >= 5
    """)
    for ip, cnt in c.fetchall():
        alerts.append({"rule_name": "BRUTE_FORCE_DETECTED", "severity": "CRITICAL",
                        "ip_address": ip, "username": "",
                        "detail": f"{cnt} failed SSH attempts from {ip}", "count": cnt})

    # Rule 2: Success after failures
    c.execute("""
        SELECT e1.ip_address, e1.username FROM events e1
        WHERE e1.event_type='SSH_SUCCESS'
          AND EXISTS (SELECT 1 FROM events e2
                      WHERE e2.event_type='SSH_FAIL' AND e2.ip_address=e1.ip_address)
        GROUP BY e1.ip_address
    """)
    for ip, user in c.fetchall():
        alerts.append({"rule_name": "SUCCESS_AFTER_FAILURES", "severity": "HIGH",
                        "ip_address": ip, "username": user,
                        "detail": f"Login succeeded from {ip} after prior failures", "count": 1})

    # Rule 3: Root login attempts
    c.execute("""
        SELECT ip_address, COUNT(*) FROM events
        WHERE (event_type='ROOT_LOGIN' OR username='root')
          AND event_type!='SSH_SUCCESS' AND ip_address!=''
        GROUP BY ip_address
    """)
    for ip, cnt in c.fetchall():
        alerts.append({"rule_name": "ROOT_LOGIN_ATTEMPT", "severity": "HIGH",
                        "ip_address": ip, "username": "root",
                        "detail": f"{cnt} root login attempt(s) from {ip}", "count": cnt})

    # Rule 4: New user created
    c.execute("SELECT username, COUNT(*) FROM events WHERE event_type='USER_CREATED' GROUP BY username")
    for user, cnt in c.fetchall():
        alerts.append({"rule_name": "NEW_USER_CREATED", "severity": "MEDIUM",
                        "ip_address": "", "username": user,
                        "detail": f"New system user created: {user}", "count": cnt})

    # Rule 5: Port scan / enumeration
    c.execute("""
        SELECT ip_address, COUNT(*) FROM events
        WHERE event_type IN ('SSH_SCAN','SSH_INVALID_USER') AND ip_address!=''
        GROUP BY ip_address HAVING COUNT(*) >= 3
    """)
    for ip, cnt in c.fetchall():
        alerts.append({"rule_name": "PORT_SCAN_DETECTED", "severity": "HIGH",
                        "ip_address": ip, "username": "",
                        "detail": f"Possible scan/enumeration from {ip} ({cnt} probes)", "count": cnt})

    for alert in alerts:
        c.execute("""
            INSERT INTO alerts (timestamp,rule_name,severity,ip_address,username,detail,count)
            VALUES (?,?,?,?,?,?,?)
        """, (datetime.now().isoformat(), alert["rule_name"], alert["severity"],
              alert["ip_address"], alert["username"], alert["detail"], alert["count"]))

    conn.commit()
    conn.close()
    return alerts


# ─── Dashboard Stats ───────────────────────────────────────────────────────────

def get_stats(db_path="siem.db"):
    conn = sqlite3.connect(db_path)
    c    = conn.cursor()

    def scalar(sql, params=()):
        c.execute(sql, params)
        return c.fetchone()[0]

    total_events = scalar("SELECT COUNT(*) FROM events")
    total_alerts = scalar("SELECT COUNT(*) FROM alerts")
    critical     = scalar("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
    unique_ips   = scalar("SELECT COUNT(DISTINCT ip_address) FROM events WHERE ip_address!=''")

    c.execute("SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY 2 DESC LIMIT 6")
    event_breakdown = [{"type": r[0], "count": r[1]} for r in c.fetchall()]

    c.execute("""SELECT ip_address, COUNT(*) as cnt FROM events
                 WHERE event_type='SSH_FAIL' AND ip_address!=''
                 GROUP BY ip_address ORDER BY cnt DESC LIMIT 5""")
    raw_attackers = c.fetchall()
    geo = geolocate_batch([r[0] for r in raw_attackers], db_path)
    top_attackers = [{"ip": r[0], "count": r[1],
                      "country": geo.get(r[0], {}).get("country", ""),
                      "city":    geo.get(r[0], {}).get("city", ""),
                      "org":     geo.get(r[0], {}).get("org", "")}
                     for r in raw_attackers]

    c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    alert_severity = {r[0]: r[1] for r in c.fetchall()}

    c.execute("""SELECT id,timestamp,rule_name,severity,ip_address,username,detail
                 FROM alerts ORDER BY id DESC LIMIT 20""")
    recent_alerts = [{"id": r[0], "timestamp": r[1], "rule": r[2],
                      "severity": r[3], "ip": r[4], "user": r[5], "detail": r[6]}
                     for r in c.fetchall()]
    alert_geo = geolocate_batch([a["ip"] for a in recent_alerts if a["ip"]], db_path)
    for a in recent_alerts:
        a["country"] = alert_geo.get(a["ip"], {}).get("country", "")

    c.execute("""SELECT id,timestamp,event_type,severity,ip_address,username,log_line
                 FROM events ORDER BY id DESC LIMIT 30""")
    recent_events = [{"id": r[0], "timestamp": r[1], "type": r[2],
                      "severity": r[3], "ip": r[4], "user": r[5], "log": r[6]}
                     for r in c.fetchall()]

    events_last_min = scalar("SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now','-1 minute')")

    conn.close()
    return {
        "total_events":    total_events,
        "total_alerts":    total_alerts,
        "critical":        critical,
        "unique_ips":      unique_ips,
        "event_breakdown": event_breakdown,
        "top_attackers":   top_attackers,
        "alert_severity":  alert_severity,
        "recent_alerts":   recent_alerts,
        "recent_events":   recent_events,
        "events_last_min": events_last_min,
    }


# ─── HTTP Server ───────────────────────────────────────────────────────────────

_HTML_CACHE = None

def _load_html():
    global _HTML_CACHE
    if _HTML_CACHE is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
        with open(path) as f:
            _HTML_CACHE = f.read()
    return _HTML_CACHE


class SIEMHandler(BaseHTTPRequestHandler):
    db_path = "siem.db"
    watcher = None

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlparse(self.path).path

        if route == "/":
            html = _load_html().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        elif route == "/api/stats":
            self._send_json(get_stats(self.db_path))

        elif route == "/api/ingest_sample":
            count = ingest_sample_logs(self.db_path)
            run_detection_rules(self.db_path)
            self._send_json({"ingested": count})

        elif route == "/api/clear":
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM geo_cache")
            conn.commit()
            conn.close()
            self._send_json({"status": "cleared"})

        elif route == "/api/watcher_status":
            self._send_json({
                "watching": self.watcher._paths if self.watcher else [],
                "active":   self.watcher is not None,
            })

        else:
            self.send_response(404)
            self.end_headers()


# ─── Entry Point ───────────────────────────────────────────────────────────────

def main():
    DB   = "siem.db"
    PORT = 8080

    init_db(DB)
    SIEMHandler.db_path = DB

    # ── Real-time file watching (uncomment to enable) ───────────────────────
    # watch_paths = ["/var/log/auth.log", "/var/log/syslog"]
    # watcher = LogFileWatcher(watch_paths, db_path=DB, poll_interval=1.0)
    # watcher.start()
    # SIEMHandler.watcher = watcher
    # ────────────────────────────────────────────────────────────────────────

    # Seed sample data on first run
    conn = sqlite3.connect(DB)
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) FROM events")
    empty = c.fetchone()[0] == 0
    conn.close()

    if empty:
        print("[*] Loading sample logs...")
        ingest_sample_logs(DB)
        run_detection_rules(DB)
        print("[*] Sample data ready.")

    server = HTTPServer(("0.0.0.0", PORT), SIEMHandler)
    print(f"[+] Mini SIEM running → http://localhost:{PORT}")
    print("[+] Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down.")
        if SIEMHandler.watcher:
            SIEMHandler.watcher.stop()
        server.server_close()


if __name__ == "__main__":
    main()
