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
  "tool": { "name": "vps-audit", "version": "4.0.0", "commit": "1a2b3c4" },
  "timestamp": "20260712_034653",
  "hostname": "web-01",
  "summary": { "pass": 14, "warn": 2, "fail": 1, "not_applicable": 0 },
  "exit_code": 1,
  "results": [
    { "id": "ssh-root-login", "test": "SSH Root Login", "status": "PASS", "severity": "high", "message": "Root login is disabled (PermitRootLogin no)", "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.", "cis": ["5.2"], "evidence": "PermitRootLogin=no", "ignored": false },
    { "id": "system-updates", "test": "System Updates", "status": "FAIL", "severity": "high", "message": "2 security update(s) pending (of 5 total) - apply immediately (run 'apt update' first for accuracy)", "remediation": "Apply pending security updates: apt-get update && apt-get upgrade.", "cis": ["1.9"], "evidence": "security=2 total=5", "ignored": false }
  ]
}
```

`severity` is the control's inherent risk weight (`critical`/`high`/`medium`/`low`/`info`), present regardless of `status` — combine for triage. `cis` is an array of indicative CIS Distribution Independent Linux Benchmark references (may be empty; guidance, not certified). `evidence` is the concrete observed value backing the result. `status` may be `NA` (not applicable, e.g. apt checks on a non-Debian host); `NA` never affects `exit_code`. `ignored` is `true` for checks excluded via `--ignore`. Per-check rationale: [`docs/checks.md`](checks.md).

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

## Markdown (`--markdown`) and HTML (`--html`)

Human-friendly, shareable reports rendered from the same results:

```bash
sudo scripts/vps-audit.sh --markdown > report.md
sudo scripts/vps-audit.sh --html     > report.html   # self-contained, inline CSS
```

Both include a summary line and a table with status, severity, check, finding,
CIS reference, and remediation.

## Drift (`--baseline FILE`)

Comparing against a prior run adds a `drift` object (and a section to the text /
Markdown reports):

```json
"drift": {
  "baseline": "baseline.json",
  "regressed": [ { "id": "ssh-root-login", "from": "PASS", "to": "FAIL" } ],
  "improved":  [ { "id": "disk-usage", "from": "WARN", "to": "PASS" } ],
  "new":       [ "some-new-check" ],
  "removed":   [ { "id": "retired-check", "from": "PASS" } ]
}
```

Add `--fail-on-drift` to make any regression a non-zero exit.

Validate locally:

```bash
sudo scripts/vps-audit.sh --json --no-public-ip > out.json
# with check-jsonschema (pip install check-jsonschema):
check-jsonschema --schemafile docs/vps-audit.schema.json out.json
```
