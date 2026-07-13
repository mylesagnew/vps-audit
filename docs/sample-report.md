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
  "tool": { "name": "vps-audit", "version": "3.3.0", "commit": "1a2b3c4" },
  "timestamp": "20260712_034653",
  "hostname": "web-01",
  "summary": { "pass": 14, "warn": 2, "fail": 1, "not_applicable": 0 },
  "exit_code": 1,
  "results": [
    { "id": "system-restart", "test": "System Restart", "status": "PASS", "severity": "low", "message": "No restart required", "remediation": "Reboot during a maintenance window to apply pending kernel/library updates.", "ignored": false },
    { "id": "ssh-root-login", "test": "SSH Root Login", "status": "PASS", "severity": "high", "message": "Root login is disabled (PermitRootLogin no)", "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.", "ignored": false },
    { "id": "system-updates", "test": "System Updates", "status": "FAIL", "severity": "high", "message": "2 security update(s) pending (of 5 total) - apply immediately (run 'apt update' first for accuracy)", "remediation": "Apply pending security updates: apt-get update && apt-get upgrade.", "ignored": false }
  ]
}
```

`severity` is the control's inherent risk weight (`critical`/`high`/`medium`/`low`/`info`) and is present regardless of `status` — combine the two for triage. `status` may be `NA` (not applicable to this host, e.g. apt checks on a non-Debian system); `NA` never affects `exit_code`. `ignored` is `true` for checks excluded from the exit code via `--ignore`.

## JSONL (`--jsonl`)

One self-contained JSON object per line (hostname/timestamp inlined) — ideal for SIEM/log pipelines:

```
{"hostname":"web-01","timestamp":"20260712_034653","id":"ssh-root-login","test":"SSH Root Login","status":"PASS","severity":"high","message":"...","remediation":"...","ignored":false}
{"hostname":"web-01","timestamp":"20260712_034653","id":"system-updates","test":"System Updates","status":"FAIL","severity":"high","message":"...","remediation":"...","ignored":false}
```

## SARIF (`--sarif`)

SARIF 2.1.0 for the GitHub code-scanning / Security tab. `FAIL`→`error`, `WARN`→`warning`, `PASS`→`note`, `NA`→`none`; `--ignore`d checks are emitted with a `suppressions` entry.

```bash
sudo scripts/vps-audit.sh --sarif --no-public-ip > vps-audit.sarif
# upload via github/codeql-action/upload-sarif in a workflow
```

Validate locally:

```bash
sudo scripts/vps-audit.sh --json --no-public-ip > out.json
# with check-jsonschema (pip install check-jsonschema):
check-jsonschema --schemafile docs/vps-audit.schema.json out.json
```
