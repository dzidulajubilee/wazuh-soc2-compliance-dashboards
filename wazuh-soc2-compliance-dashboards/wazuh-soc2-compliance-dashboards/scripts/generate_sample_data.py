#!/usr/bin/env python3
"""
SOC 2 Compliance Dashboard Suite — Unified Sample Data Generator
Generates realistic data for ALL 5 Trust Services Criteria dashboards:
  CC5 (Control Activities), CC6 (Access Controls), CC7 (System Operations),
  CC8 (Change Management), A1 (Availability)

Usage:
    python3 generate_all_sample_data.py --password <INDEXER_PASSWORD>
    python3 generate_all_sample_data.py --dry-run
"""

import json, random, argparse, sys, os
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
USERS = ["admin", "deploy", "svc-monitor", "hamza", "ops-team", "backup-agent"]
ATK_USERS = ["root", "admin", "test", "guest", "oracle", "postgres", "ftpuser"]
IPS_OK = ["10.0.10.5", "10.0.10.12", "10.0.10.88", "192.168.1.100"]
IPS_BAD = ["185.220.101.34", "45.155.205.233", "193.42.33.14", "91.240.118.172", "103.145.27.89"]

def evt(ts, agent, rule_id, level, desc, groups, extra_data=None, tsc=None, mitre=None):
    e = {"@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
         "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
         "manager": {"name": "wazuh-manager"},
         "rule": {"id": str(rule_id), "level": level, "description": desc, "groups": groups,
                  "tsc": tsc or [], "pci_dss": [], "nist_800_53": []},
         "data": extra_data or {}, "location": "syslog"}
    if mitre:
        e["rule"]["mitre"] = mitre
    return e

def rts(base, h_range=(0,23)):
    return base + timedelta(hours=random.randint(*h_range), minutes=random.randint(0,59), seconds=random.randint(0,59))

# ================================================================
# CC5 — SCA DATA
# ================================================================
SCA_CHECKS = [
    (28500, "Ensure permissions on /etc/passwd are configured", 0.9, "chmod 644 /etc/passwd", ["CC5.2","CC6.1"]),
    (28510, "Ensure SSH root login is disabled", 0.7, "Set PermitRootLogin no in sshd_config", ["CC5.2","CC6.1"]),
    (28520, "Ensure iptables default deny firewall policy", 0.5, "iptables -P INPUT DROP", ["CC5.1","CC5.2"]),
    (28530, "Ensure audit log storage size is configured", 0.65, "Set max_log_file in auditd.conf", ["CC5.2","CC7.2"]),
    (28540, "Ensure password creation requirements are configured", 0.6, "Configure pwquality.conf", ["CC5.3","CC6.1"]),
    (28550, "Ensure rsyslog is installed", 0.92, "apt install rsyslog", ["CC5.1","CC7.2"]),
    (28560, "Ensure filesystem integrity is regularly checked", 0.55, "Install and configure AIDE", ["CC5.1","CC8.1"]),
    (28570, "Ensure access to su command is restricted", 0.72, "Configure pam_wheel.so", ["CC5.3","CC6.1"]),
    (30001, "Ensure account lockout threshold is set to 5 or fewer", 0.8, "Configure via Group Policy", ["CC5.2","CC6.1"]),
    (30020, "Ensure Windows Firewall Domain state is On", 0.85, "Enable via Group Policy", ["CC5.2","CC6.6"]),
    (30040, "Ensure minimum password length is 14+ characters", 0.65, "Configure Password Policy GPO", ["CC5.3","CC6.1"]),
    (30050, "Ensure BitLocker Drive Encryption is enabled", 0.55, "Enable BitLocker", ["CC5.2","CC6.7"]),
]

def gen_cc5(start, end):
    events = []
    day = start
    prev = {}
    while day <= end:
        for scan in range(2):
            ts = day + timedelta(hours=scan*12+random.randint(0,2), minutes=random.randint(0,59))
            if ts > end: break
            for agent in AGENTS:
                passed, failed, na = 0, 0, 0
                for chk_id, title, bias, remed, tsc in SCA_CHECKS:
                    improve = min(0.1, (day-start).days/DAYS*0.15)
                    r = random.random()
                    if r < min(0.98, bias+improve): result, passed = "passed", passed+1
                    elif r < min(0.98, bias+improve)+0.05: result, na = "", na+1
                    else: result, failed = "failed", failed+1
                    key = f"{agent['id']}_{chk_id}"
                    prev_r = prev.get(key, "")
                    prev[key] = result
                    events.append(evt(ts, agent, "19056" if result=="passed" else "19057", 3 if result=="passed" else 7,
                        f"SCA check: {title}", ["sca"], tsc=tsc,
                        extra_data={"sca":{"type":"check","scan_id":str(int(ts.timestamp())),"policy":"cis_benchmark.yml",
                            "check":{"id":chk_id,"title":title,"result":result,"previous_result":prev_r,
                                     "remediation":remed,"compliance":{"tsc":tsc}}}}))
                total = passed+failed+na
                score = round((passed/max(total-na,1))*100,1)
                events.append(evt(ts, agent, "19052", 4, "SCA summary: CIS Benchmark", ["sca"],
                    tsc=["CC5.1","CC5.2","CC5.3"],
                    extra_data={"sca":{"type":"summary","name":"CIS Benchmark","score":score,
                        "passed":passed,"failed":failed,"invalid":na,"total_checks":total}}))
        day += timedelta(days=1)
    return events

# ================================================================
# CC6 — AUTH / ACCESS DATA
# ================================================================
def gen_cc6(start, end):
    events = []
    day = start
    while day <= end:
        for agent in AGENTS:
            is_lin = agent["id"] != "004"
            # Auth failures
            fc = random.randint(5,20)
            if random.random() < 0.08: fc = random.randint(80,200)
            for _ in range(fc):
                ts = rts(day)
                if ts > end: break
                events.append(evt(ts, agent, "5710" if is_lin else "60122", 5,
                    "sshd: Attempt to login using a non-existent user" if is_lin else "Windows: Logon failure",
                    ["syslog","sshd","authentication_failed"] if is_lin else ["windows","windows_security","authentication_failed"],
                    tsc=["CC6.1","CC6.8","CC7.2","CC7.3"],
                    extra_data={"srcip": random.choice(IPS_BAD if random.random()<0.7 else IPS_OK),
                                "dstuser": random.choice(ATK_USERS if random.random()<0.6 else USERS)},
                    mitre={"id":["T1110"],"tactic":["Credential Access"],"technique":["Brute Force"]}))
            if fc > 50:
                events.append(evt(rts(day,(2,22)), agent, "5712" if is_lin else "60204", 10,
                    "Multiple authentication failures — possible brute force",
                    ["syslog","sshd","authentication_failures"] if is_lin else ["windows","windows_security","authentication_failures"],
                    tsc=["CC6.1","CC6.8","CC7.2","CC7.3"],
                    extra_data={"srcip":random.choice(IPS_BAD),"dstuser":random.choice(ATK_USERS)},
                    mitre={"id":["T1110"],"tactic":["Credential Access"],"technique":["Brute Force"]}))
            # Auth success
            for _ in range(random.randint(10,40)):
                ts = rts(day,(6,22))
                if ts > end: break
                events.append(evt(ts, agent, "5715" if is_lin else "60106", 3,
                    "sshd: Authentication success" if is_lin else "Windows: Logon success",
                    ["syslog","sshd","authentication_success"] if is_lin else ["windows","windows_security","authentication_success"],
                    tsc=["CC6.1","CC7.2"],
                    extra_data={"srcip":random.choice(IPS_OK),"dstuser":random.choice(USERS)}))
            # Account changes
            if random.random() < 0.15:
                for _ in range(random.randint(1,3)):
                    events.append(evt(rts(day,(9,17)), agent, "5901", 8, "New user added to the system",
                        ["syslog","adduser"], tsc=["CC6.1","CC6.2","CC6.3"],
                        extra_data={"dstuser":random.choice(["newuser01","contractor-temp","svc-deploy","audit-user"]),
                                    "srcuser":"root" if is_lin else "Administrator"},
                        mitre={"id":["T1136"],"tactic":["Persistence"],"technique":["Create Account"]}))
            # Sudo (Linux)
            if is_lin:
                for _ in range(random.randint(3,12)):
                    ts = rts(day,(8,20))
                    if ts > end: break
                    events.append(evt(ts, agent, "5401", 4, "sudo: Successful sudo to root",
                        ["syslog","sudo"], tsc=["CC6.1","CC6.3"],
                        extra_data={"srcuser":random.choice(USERS),"dstuser":"root"},
                        mitre={"id":["T1548.003"],"tactic":["Privilege Escalation"],"technique":["Sudo and Sudo Caching"]}))
        day += timedelta(days=1)
    return events

# ================================================================
# CC7 — VULNERABILITY + HIGH SEVERITY ALERTS
# ================================================================
CVES = [("CVE-2024-6387","openssh","9.7p1","Critical"),("CVE-2024-3094","xz-utils","5.6.1","Critical"),
        ("CVE-2023-44487","nginx","1.25.3","High"),("CVE-2023-38545","curl","8.4.0","High"),
        ("CVE-2023-4911","glibc","2.38","High"),("CVE-2024-21626","runc","1.1.11","High"),
        ("CVE-2023-36884","msoffice","16.0","High"),("CVE-2023-23397","outlook","16.0","Critical"),
        ("CVE-2024-1086","kernel","6.1.0","High"),("CVE-2023-32233","kernel","6.3.1","Medium")]
TACTICS = ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
           "Credential Access","Discovery","Lateral Movement","Collection","Exfiltration"]
TECHNIQUES = ["Exploit Public-Facing Application","Command and Scripting Interpreter","Boot or Logon Autostart",
              "Process Injection","Obfuscated Files","OS Credential Dumping","Network Service Discovery",
              "Remote Services","Data from Local System","Exfiltration Over Web Service"]

def gen_cc7(start, end):
    events = []
    day = start
    while day <= end:
        for agent in AGENTS:
            # Vulnerabilities: 2-8 per day per agent
            for _ in range(random.randint(2,8)):
                ts = rts(day)
                if ts > end: break
                cve, pkg, ver, sev = random.choice(CVES)
                events.append(evt(ts, agent, "23503", 7 if sev in ("Medium","High") else 10,
                    f"Vulnerability detected: {cve} in {pkg}", ["vulnerability-detector"],
                    tsc=["CC7.1","CC7.2"],
                    extra_data={"vulnerability":{"cve":cve,"severity":sev,"package":{"name":pkg,"version":ver},
                        "reference":f"https://nvd.nist.gov/vuln/detail/{cve}","status":"Active"}}))
            # High severity alerts: 1-5 per day
            for _ in range(random.randint(1,5)):
                ts = rts(day)
                if ts > end: break
                lvl = random.choice([10,11,12,13,14])
                tactic = random.choice(TACTICS)
                technique = random.choice(TECHNIQUES)
                events.append(evt(ts, agent, random.choice(["87105","87106","92657","92210","80790"]), lvl,
                    f"Threat detected: {technique}", ["attack",tactic.lower().replace(" ","_")],
                    tsc=["CC7.2","CC7.3","CC7.4"],
                    mitre={"id":[f"T{random.randint(1000,1600)}"],"tactic":[tactic],"technique":[technique]}))
        day += timedelta(days=1)
    return events

# ================================================================
# CC8 — FIM / SYSCHECK DATA
# ================================================================
FIM_PATHS_LINUX = ["/etc/passwd","/etc/shadow","/etc/ssh/sshd_config","/etc/hosts","/etc/crontab",
    "/etc/sudoers","/var/log/auth.log","/etc/nginx/nginx.conf","/etc/mysql/my.cnf",
    "/opt/app/config/application.yml","/etc/resolv.conf","/etc/fstab","/etc/pam.d/common-auth"]
FIM_PATHS_WIN = ["C:\\Windows\\System32\\drivers\\etc\\hosts","C:\\Windows\\System32\\config\\SAM",
    "C:\\Program Files\\app\\config.xml","C:\\Windows\\System32\\GroupPolicy\\Machine\\Registry.pol",
    "C:\\Users\\Public\\Documents\\report.docx"]

def gen_cc8(start, end):
    events = []
    day = start
    while day <= end:
        for agent in AGENTS:
            is_lin = agent["id"] != "004"
            paths = FIM_PATHS_LINUX if is_lin else FIM_PATHS_WIN
            # FIM events: 3-15 per day per agent
            for _ in range(random.randint(3,15)):
                ts = rts(day)
                if ts > end: break
                path = random.choice(paths)
                event_type = random.choices(["modified","added","deleted"], weights=[70,20,10])[0]
                lvl = 5 if event_type == "modified" else (3 if event_type == "added" else 7)
                if path in ("/etc/shadow","/etc/sudoers","C:\\Windows\\System32\\config\\SAM"):
                    lvl = max(lvl, 10)
                events.append(evt(ts, agent, "550" if event_type=="modified" else ("554" if event_type=="added" else "553"), lvl,
                    f"File integrity: {event_type} - {path}", ["ossec","syscheck",f"syscheck_{event_type}"],
                    tsc=["CC8.1","CC5.2"],
                    extra_data={"syscheck":{"path":path,"event":event_type}}))
        day += timedelta(days=1)
    return events

# ================================================================
# A1 — AGENT AVAILABILITY DATA
# ================================================================
def gen_a1(start, end):
    events = []
    day = start
    while day <= end:
        for agent in AGENTS:
            # Wazuh system health events: 2-5 per day
            for _ in range(random.randint(2,5)):
                ts = rts(day)
                if ts > end: break
                events.append(evt(ts, agent, "502", 3, "Wazuh agent started", ["wazuh"],
                    tsc=["A1.1","A1.2"]))
            # Disconnection: 0-2 per day, rare
            if random.random() < 0.12:
                ts = rts(day)
                events.append(evt(ts, agent, "503", 8 if random.random()<0.3 else 5,
                    "Agent disconnected — endpoint lost contact with manager",
                    ["wazuh","agent_disconnected"], tsc=["A1.1"]))
                # Reconnection usually follows within hours
                if random.random() < 0.85:
                    recon_ts = ts + timedelta(minutes=random.randint(5,180))
                    if recon_ts <= end:
                        events.append(evt(recon_ts, agent, "504", 3,
                            "Agent reconnected — endpoint restored to monitoring",
                            ["wazuh"], tsc=["A1.1","A1.2"]))
        day += timedelta(days=1)
    return events


# ================================================================
# MAIN
# ================================================================
def bulk_payload(events):
    lines = []
    for e in events:
        ts = datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%S.000+0000")
        lines.append(json.dumps({"index": {"_index": f"{IDX}{ts.strftime('%Y.%m.%d')}"}}))
        lines.append(json.dumps(e))
    return lines

def main():
    p = argparse.ArgumentParser(description="Generate sample data for all SOC 2 dashboards")
    p.add_argument("--indexer-url", default="https://127.0.0.1:9200")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--days", type=int, default=DAYS)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--output-dir", default=".")
    args = p.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    print(f"Date range: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}")
    print(f"Agents: {len(AGENTS)}\n")

    generators = [
        ("CC5 — Control Activities (SCA)", gen_cc5),
        ("CC6 — Logical Access Controls (Auth)", gen_cc6),
        ("CC7 — System Operations (Vuln + Threats)", gen_cc7),
        ("CC8 — Change Management (FIM)", gen_cc8),
        ("A1  — Availability (Agent Health)", gen_a1),
    ]

    all_events = []
    for name, gen_fn in generators:
        print(f"Generating {name}...", end=" ")
        evts = gen_fn(start, end)
        print(f"{len(evts):,} events")
        all_events.extend(evts)

    print(f"\nTotal: {len(all_events):,} events across all criteria")

    if args.dry_run:
        os.makedirs(args.output_dir, exist_ok=True)
        outfile = os.path.join(args.output_dir, "soc2_all_sample_data.ndjson")
        with open(outfile, "w") as f:
            for e in all_events:
                f.write(json.dumps(e) + "\n")
        print(f"\nDry-run complete. Written to: {outfile}")
        return

    import urllib.request, ssl, base64
    lines = bulk_payload(all_events)
    chunk_size = 2000
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    print(f"\nIndexing into {args.indexer_url}...")
    success, errors = 0, 0
    total_chunks = (len(lines) // chunk_size) + 1
    for i in range(0, len(lines), chunk_size):
        chunk = lines[i:i+chunk_size]
        req = urllib.request.Request(f"{args.indexer_url}/_bulk",
            data=("\n".join(chunk)+"\n").encode("utf-8"),
            headers={"Content-Type":"application/x-ndjson","Authorization":f"Basic {auth}"}, method="POST")
        try:
            resp = urllib.request.urlopen(req, context=ssl_ctx)
            result = json.loads(resp.read())
            n = len(chunk)//2
            if result.get("errors"):
                err = sum(1 for item in result.get("items",[]) if "error" in item.get("index",{}))
                errors += err; success += n - err
            else:
                success += n
            cn = (i//chunk_size)+1
            if cn % 10 == 0 or cn == total_chunks:
                print(f"  Chunk {cn}/{total_chunks} — {success:,} indexed so far")
        except Exception as e:
            print(f"  ERROR: {e}")
            errors += len(chunk)//2

    print(f"\nComplete. Success: {success:,} | Errors: {errors:,}")
    print(f"\nOpen your Wazuh Dashboard, set time range to Last 90 days.")
    print(f"All 5 SOC 2 dashboards should now populate with data.")

if __name__ == "__main__":
    main()
