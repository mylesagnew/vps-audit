# Sample output

## Console / text report

```
VPS Security Audit Tool
https://github.com/mylesagnew/vps-audit
Starting audit at Sun Jul 12 03:46:53 UTC 2026

System Information
Hostname: web-01
Operating System: Debian GNU/Linux 12 (bookworm)
Kernel Version: 6.1.0-21-amd64
CPU Cores: 2
Total Memory: 3.8Gi
Public IP: 203.0.113.10

Security Audit Results
[PASS] System Restart - No restart required
[PASS] SSH Root Login - Root login is disabled (PermitRootLogin no)
[PASS] SSH Password Auth - Password authentication is disabled, key-based auth only
[WARN] SSH Port - Using default port 22 - a non-standard port reduces automated scanning noise
[PASS] Firewall Status (UFW) - UFW is active and enforcing rules
[PASS] Intrusion Prevention - Fail2ban or CrowdSec is installed and running
[PASS] Failed Logins - 3 failed login attempts (/var/log/auth.log) - within normal range
[FAIL] System Updates - 2 security update(s) pending (of 5 total) - apply immediately
[PASS] Port Security - 2 internet-facing ports [22,443] (total listening: 4 [22,443,5432,6379])
...
Summary: PASS=14 WARN=2 FAIL=1
```

## JSON (`--json`)

Validates against [`vps-audit.schema.json`](vps-audit.schema.json).

```json
{
  "timestamp": "20260712_034653",
  "hostname": "web-01",
  "summary": { "pass": 14, "warn": 2, "fail": 1 },
  "exit_code": 1,
  "results": [
    { "test": "System Restart", "status": "PASS", "message": "No restart required" },
    { "test": "SSH Root Login", "status": "PASS", "message": "Root login is disabled (PermitRootLogin no)" },
    { "test": "System Updates", "status": "FAIL", "message": "2 security update(s) pending (of 5 total) - apply immediately (run 'apt update' first for accuracy)" }
  ]
}
```

Validate locally:

```bash
sudo scripts/vps-audit.sh --json --no-public-ip > out.json
# with check-jsonschema (pip install check-jsonschema):
check-jsonschema --schemafile docs/vps-audit.schema.json out.json
```
