# Wazuh SOC 2 Compliance Dashboard Suite

Open-source SOC 2 Trust Services Criteria compliance dashboards for Wazuh 4.14.x. Five dashboards covering CC5, CC6, CC7, CC8, and A1 — built from an auditor's perspective with full TSC compliance language.

Designed for compliance officers, auditors, and security teams preparing for SOC 2 Type 2 examinations.

---

## Why This Exists

Wazuh ships a native TSC module that tags events with `rule.tsc` fields. It shows a list of tagged alerts filtered by criterion. That is a starting point — not what an auditor needs.

Auditors need compliance posture scores, trend analysis over a 90-day evidence period, remediation registers, per-endpoint breakdowns, and audit trails. These dashboards provide exactly that, using data Wazuh already collects.

No custom index patterns. No transforms. No ingest pipelines. Import and go.

---

## Dashboards

| Dashboard | File | Trust Services Criterion | Wazuh Data Source |
|---|---|---|---|
| CC5 — Control Activities | `soc2_cc5_control_activities.ndjson` | COSO Principles 10–12: control design, technology general controls, policy enforcement | Security Configuration Assessment (SCA) |
| CC6 — Logical and Physical Access | `soc2_cc6_access_controls.ndjson` | CC6.1–CC6.8: authentication, account lifecycle, privilege escalation, boundary protection | Authentication events, account management, sudo |
| CC7 — System Operations | `soc2_cc7_system_operations.ndjson` | CC7.1–CC7.4: vulnerability detection, threat monitoring, MITRE ATT&CK mapping, incident evaluation | Vulnerability Detector, high-severity alerts |
| CC8 — Change Management | `soc2_cc8_change_management.ndjson` | CC8.1: change authorization, file integrity, unauthorized modification detection | File Integrity Monitoring (FIM / Syscheck) |
| A1 — Availability | `soc2_a1_availability.ndjson` | A1.1–A1.2: system availability, endpoint health, monitoring continuity | Agent lifecycle events |

Each dashboard contains 15 visualizations. 75 total across the suite.

---

## Installation

Tested on Wazuh 4.14.7 with OpenSearch Dashboards 2.19.x.

**Step 1** — Open Wazuh Dashboard. Navigate to Stack Management, then Saved Objects, then Import.

**Step 2** — Upload each `.ndjson` file from the `dashboards/` folder. When prompted about the index pattern conflict, select your existing `wazuh-alerts-*` index pattern.

**Step 3** — Open the imported dashboard from the Dashboards list. Set the time range to your evidence period (default: last 90 days for SOC 2 Type 2).

Repeat for each dashboard. Order does not matter.

---

## Testing with Sample Data

If you need test data before connecting real agents:

```bash
# Generate and index 46,000+ events across all 5 criteria
python3 scripts/generate_sample_data.py --password <YOUR_INDEXER_PASSWORD>

# Or dry-run to inspect the data first
python3 scripts/generate_sample_data.py --dry-run
```

The script generates 90 days of realistic events: SCA checks, authentication events (with brute force spikes), vulnerability detections, file integrity changes, and agent availability data across 5 simulated endpoints.

---

## What Each Dashboard Covers

### CC5 — Control Activities

Answers: "Are your configuration controls designed and operating effectively?"

- Control Effectiveness Score (SCA compliance gauge)
- Compliance trend over the 90-day evidence period with 80% threshold line
- Policy baseline comparison (which CIS Benchmarks are weakest)
- Remediation register with failed checks, remediation guidance, and affected endpoints
- Control status change audit trail (passed/failed transitions)

### CC6 — Logical and Physical Access Controls

Answers: "Who accessed what, and were unauthorized attempts detected and investigated?"

- Authentication failure and success metrics
- Failed authentication trend by endpoint over the evidence period
- Source IP analysis of unauthorized access attempts (CC6.6 boundary evidence)
- Targeted user account analysis
- Brute force indicator table with source, target, endpoint, and detection rule
- Account provisioning and deprovisioning audit trail (CC6.2/CC6.3)
- Privilege escalation audit log

### CC7 — System Operations

Answers: "Are vulnerabilities identified, threats detected, and incidents evaluated?"

- Vulnerability count and detection trend over the evidence period
- Top CVEs and most vulnerable endpoints
- MITRE ATT&CK tactic and technique mapping
- High-severity alert evidence log
- Detection category distribution

### CC8 — Change Management

Answers: "Are changes to systems detected, classified, and authorized?"

- File modification, addition, and deletion metrics
- Change activity trend with type breakdown
- Most frequently changed files
- Unauthorized change register (high-severity FIM alerts)
- Complete change audit trail with file path, type, endpoint, and detection context

### A1 — Availability

Answers: "Are systems available and is monitoring continuous?"

- Agent disconnection and reconnection tracking
- Endpoint availability trend over the evidence period
- Disconnection frequency by system
- Reconnection recovery evidence
- Monitoring infrastructure health events

---

## Auditor Usage Guide

1. Set the dashboard time range to your SOC 2 Type 2 examination evidence period (typically 90 days).
2. Use the trend charts to demonstrate sustained control operating effectiveness — consistency over the period is what auditors evaluate.
3. Export data tables as CSV for inclusion in evidence packages.
4. Use the Reporting feature in OpenSearch Dashboards to generate PDF snapshots for the auditor evidence binder.
5. The remediation registers (CC5, CC8) and audit trails (CC6, CC8, A1) are designed for direct auditor review.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Wazuh Manager | 4.14.x |
| Wazuh Dashboard (OpenSearch Dashboards) | 2.x |
| Wazuh Agents | 4.14.x with default modules enabled |

The dashboards use data from modules enabled by default: SCA, log collection (authentication), Vulnerability Detector, File Integrity Monitoring, and agent lifecycle events. No additional agent configuration is required for most deployments.

---

## Repository Structure

```
wazuh-soc2-compliance-dashboards/
├── README.md
├── LICENSE
├── dashboards/
│   ├── soc2_cc5_control_activities.ndjson
│   ├── soc2_cc6_access_controls.ndjson
│   ├── soc2_cc7_system_operations.ndjson
│   ├── soc2_cc8_change_management.ndjson
│   └── soc2_a1_availability.ndjson
├── scripts/
│   ├── generate_sample_data.py
│   └── generate_cc8_sample_data.py
└── docs/
    └── images/
```

---

## References

- [Wazuh TSC Compliance Documentation](https://documentation.wazuh.com/current/compliance/tsc/index.html)
- [Wazuh SCA Module](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html)
- [Wazuh FIM Module](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Wazuh Vulnerability Detector](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html)
- [AICPA Trust Services Criteria (2017)](https://us.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria.pdf)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Wazuh Integrations Repository](https://github.com/wazuh/integrations)

---

## Author

Hamza Jameel — Information Security Engineer | Wazuh Ambassador

- [LinkedIn](https://www.linkedin.com/in/hamzahx10/)
- [Portfolio](https://dshamzaj.github.io/)
- [GitHub](https://github.com/DShamzaj)

---

## License

This project is released under the [MIT License](LICENSE). Free to use, modify, and distribute.
