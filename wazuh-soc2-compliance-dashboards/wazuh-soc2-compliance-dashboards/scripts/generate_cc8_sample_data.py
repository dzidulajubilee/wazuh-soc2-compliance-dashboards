#!/usr/bin/env python3
"""
SOC 2 CC8 — Change Management Sample Data Generator (Fixed)
Generates FIM/syscheck events with correct field paths:
  syscheck.path (NOT data.syscheck.path)
  syscheck.event (NOT data.syscheck.event)

Usage:
    python3 generate_cc8_sample_data.py --password <INDEXER_PASSWORD>
    python3 generate_cc8_sample_data.py --dry-run
"""

import json, random, argparse, sys
from datetime import datetime, timedelta, timezone

DAYS = 90
IDX = "wazuh-alerts-4.x-"

AGENTS = [
    {"id": "001", "name": "web-server-prod-01", "ip": "10.0.1.10"},
    {"id": "002", "name": "db-server-prod-01", "ip": "10.0.2.20"},
    {"id": "003", "name": "app-server-prod-01", "ip": "10.0.3.30"},
    {"id": "004", "name": "win-workstation-01", "ip": "10.0.4.40"},
    {"id": "005", "name": "linux-jumpbox-01", "ip": "10.0.5.50"},
]

LINUX_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/ssh/sshd_config", "/etc/hosts", "/etc/hostname",
    "/etc/crontab", "/etc/sudoers", "/etc/sudoers.d/custom",
    "/etc/rsyslog.conf", "/etc/resolv.conf", "/etc/fstab",
    "/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default",
    "/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf",
    "/etc/pam.d/common-auth", "/etc/pam.d/common-password",
    "/etc/security/limits.conf", "/etc/sysctl.conf",
    "/etc/apt/sources.list", "/etc/logrotate.conf",
    "/opt/app/config/application.yml", "/opt/app/config/database.yml",
    "/var/www/html/index.html", "/var/www/html/wp-config.php",
    "/usr/local/bin/backup.sh", "/root/.bashrc", "/root/.ssh/authorized_keys",
]

WINDOWS_PATHS = [
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\config\\SOFTWARE",
    "C:\\Windows\\System32\\GroupPolicy\\Machine\\Registry.pol",
    "C:\\Windows\\System32\\Tasks\\ScheduledTask",
    "C:\\Program Files\\App\\config.xml",
    "C:\\Program Files\\App\\settings.json",
    "C:\\Users\\Public\\Documents\\report.docx",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1",
]

# Critical paths get higher severity
CRITICAL_PATHS = {
    "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys", "/etc/pam.d/common-auth",
    "C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\System32\\config\\SYSTEM",
}


def generate_cc8_events(start, end):
    events = []
    day = start

    while day <= end:
        for agent in AGENTS:
            is_linux = agent["id"] != "004"
            paths = LINUX_PATHS if is_linux else WINDOWS_PATHS

            # 5-20 FIM events per day per agent
            num_events = random.randint(5, 20)
            # Occasional spike days (config deployments, patch days)
            if random.random() < 0.05:
                num_events = random.randint(40, 80)

            for _ in range(num_events):
                ts = day + timedelta(
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59)
                )
                if ts > end:
                    break

                path = random.choice(paths)
                event_type = random.choices(
                    ["modified", "added", "deleted"],
                    weights=[70, 20, 10]
                )[0]

                # Determine severity
                if path in CRITICAL_PATHS:
                    level = random.choice([10, 11, 12]) if event_type != "added" else 8
                elif event_type == "deleted":
                    level = random.choice([7, 8])
                elif event_type == "modified":
                    level = random.choice([5, 7])
                else:
                    level = random.choice([3, 5])

                # Rule IDs matching Wazuh defaults
                if event_type == "modified":
                    rule_id = "550"
                    rule_desc = f"Integrity checksum changed for: '{path}'"
                elif event_type == "added":
                    rule_id = "554"
                    rule_desc = f"File added to the system: '{path}'"
                else:
                    rule_id = "553"
                    rule_desc = f"File deleted from the system: '{path}'"

                # Generate realistic file metadata
                size_before = random.randint(100, 50000) if event_type == "modified" else 0
                size_after = random.randint(100, 50000) if event_type != "deleted" else 0

                event = {
                    "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                    "agent": {
                        "id": agent["id"],
                        "name": agent["name"],
                        "ip": agent["ip"]
                    },
                    "manager": {"name": "wazuh-manager"},
                    "rule": {
                        "id": rule_id,
                        "level": level,
                        "description": rule_desc,
                        "groups": ["ossec", "syscheck", f"syscheck_{event_type}"],
                        "tsc": ["CC8.1", "CC5.2"],
                        "pci_dss": ["11.5"],
                        "nist_800_53": ["SI-7"],
                        "firedtimes": random.randint(1, 500)
                    },
                    # TOP-LEVEL syscheck — this is the correct field path
                    "syscheck": {
                        "path": path,
                        "event": event_type,
                        "size_before": str(size_before) if size_before else None,
                        "size_after": str(size_after) if size_after else None,
                        "uid_after": "0" if is_linux else None,
                        "gid_after": "0" if is_linux else None,
                        "perm_after": "rw-r--r--" if is_linux else None,
                        "uname_after": "root" if is_linux else "SYSTEM",
                        "gname_after": "root" if is_linux else None,
                        "md5_before": f"{random.getrandbits(128):032x}" if event_type == "modified" else None,
                        "md5_after": f"{random.getrandbits(128):032x}" if event_type != "deleted" else None,
                        "sha1_before": f"{random.getrandbits(160):040x}" if event_type == "modified" else None,
                        "sha1_after": f"{random.getrandbits(160):040x}" if event_type != "deleted" else None,
                        "sha256_before": f"{random.getrandbits(256):064x}" if event_type == "modified" else None,
                        "sha256_after": f"{random.getrandbits(256):064x}" if event_type != "deleted" else None,
                    },
                    "location": "syscheck",
                    "decoder": {"name": "syscheck_integrity_changed" if event_type == "modified" else "syscheck_new_entry"}
                }

                # Clean None values from syscheck
                event["syscheck"] = {k: v for k, v in event["syscheck"].items() if v is not None}

                events.append(event)

        day += timedelta(days=1)

    return events


def main():
    p = argparse.ArgumentParser(description="Generate CC8 FIM sample data for Wazuh")
    p.add_argument("--indexer-url", default="https://127.0.0.1:9200")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--days", type=int, default=DAYS)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--output", default="cc8_sample_data.ndjson")
    args = p.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)

    print(f"Generating CC8 Change Management sample data...")
    print(f"  Agents: {len(AGENTS)}")
    print(f"  Date range: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}")

    events = generate_cc8_events(start, end)
    print(f"  Generated: {len(events):,} events")

    # Breakdown
    mods = sum(1 for e in events if e["syscheck"]["event"] == "modified")
    adds = sum(1 for e in events if e["syscheck"]["event"] == "added")
    dels = sum(1 for e in events if e["syscheck"]["event"] == "deleted")
    high = sum(1 for e in events if e["rule"]["level"] >= 7)
    print(f"  Modified: {mods:,} | Added: {adds:,} | Deleted: {dels:,}")
    print(f"  High severity (level 7+): {high:,}")

    if args.dry_run:
        with open(args.output, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        print(f"\nDry-run complete. Written to: {args.output}")
        print(f"\nVerify field paths are correct:")
        print(f'  syscheck.path: {events[0]["syscheck"]["path"]}')
        print(f'  syscheck.event: {events[0]["syscheck"]["event"]}')
        print(f'  rule.groups: {events[0]["rule"]["groups"]}')
        return

    # Bulk index
    import urllib.request, ssl, base64
    lines = []
    for e in events:
        ts = datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%S.000+0000")
        lines.append(json.dumps({"index": {"_index": f"{IDX}{ts.strftime('%Y.%m.%d')}"}}))
        lines.append(json.dumps(e))

    chunk_size = 2000
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    print(f"\nIndexing {len(events):,} events into {args.indexer_url}...")
    success, errors = 0, 0
    total_chunks = (len(lines) // chunk_size) + 1

    for i in range(0, len(lines), chunk_size):
        chunk = lines[i:i + chunk_size]
        req = urllib.request.Request(
            f"{args.indexer_url}/_bulk",
            data=("\n".join(chunk) + "\n").encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson", "Authorization": f"Basic {auth}"},
            method="POST"
        )
        try:
            resp = urllib.request.urlopen(req, context=ssl_ctx)
            result = json.loads(resp.read())
            n = len(chunk) // 2
            if result.get("errors"):
                err = sum(1 for item in result.get("items", []) if "error" in item.get("index", {}))
                errors += err
                success += n - err
            else:
                success += n
            cn = (i // chunk_size) + 1
            print(f"  Chunk {cn}/{total_chunks}: {success:,} indexed")
        except Exception as e:
            print(f"  ERROR: {e}")
            errors += len(chunk) // 2

    print(f"\nComplete. Success: {success:,} | Errors: {errors:,}")
    print(f"\nOpen CC8 dashboard, set time range to Last 90 days.")


if __name__ == "__main__":
    main()
