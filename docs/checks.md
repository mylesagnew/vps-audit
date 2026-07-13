# Checks reference

Every check has a stable `id` (used in JSON/JSONL/SARIF, `--ignore`, `--fail-on`),
an inherent `severity`, and an indicative CIS control mapping. `severity` is the
control's risk weight and is reported regardless of the result — combine it with
`status` for triage.

> **CIS mappings are indicative**, based on the CIS Distribution Independent Linux
> Benchmark. They are guidance for orientation, not a certified mapping — verify
> against the exact benchmark version and profile you must comply with.

Statuses: **PASS** (control satisfied), **WARN** (review), **FAIL** (act),
**NA** (not applicable to this host — never affects the exit code).

| id | Severity | CIS | What it checks | PASS / WARN / FAIL |
|----|----------|-----|----------------|--------------------|
| `system-restart` | low | – | `/var/run/reboot-required` present | PASS: none / — / WARN: reboot pending |
| `ssh-root-login` | high | 5.2 | Effective `PermitRootLogin` (`sshd -T`) | PASS: `no` / WARN: key-only (`prohibit-password`…) / FAIL: `yes` |
| `ssh-password-auth` | high | 5.2 | Effective `PasswordAuthentication` | PASS: `no` / — / FAIL: `yes` |
| `ssh-port` | low | – | Effective `Port` vs `ip_unprivileged_port_start` | PASS: non-default privileged / WARN: 22 / FAIL: unprivileged port |
| `ssh-config` | info | – | Could the effective SSH config be read | — / WARN: unreadable / — |
| `firewall` | high | 3.5 | ufw/firewalld active, or nft/iptables with a deny policy | PASS: enforcing / WARN: rules but ACCEPT policy / FAIL: none/inactive |
| `unattended-upgrades` | medium | 1.9 | `unattended-upgrades` installed (Debian/Ubuntu) | PASS: installed / — / FAIL: missing (NA off-Debian) |
| `intrusion-prevention` | medium | – | Fail2ban/CrowdSec installed & running (host or container) | PASS: running / WARN: installed only / FAIL: absent |
| `auth-log` | info | – | Auth log / journal readable | — / WARN: unreadable / — |
| `failed-logins` | medium | – | Count of failed SSH logins (rotation-aware) | PASS: `<WARN` / WARN / FAIL: `>=FAIL` threshold |
| `system-updates` | high | 1.9 | Pending apt updates, security vs non-security | PASS: none / WARN: non-security / FAIL: security (NA: no apt) |
| `running-services` | low | 2.2 | Count of running systemd services | threshold-based |
| `port-security` | high | 2.2 | Internet-facing (non-loopback) listening ports | threshold-based on public port count |
| `disk-usage` | medium | – | `/` usage percent | PASS `<50` / WARN `<80` / FAIL (policy-tunable) |
| `memory-usage` | low | – | Memory usage percent | PASS `<50` / WARN `<80` / FAIL |
| `cpu-usage` | low | – | CPU usage percent (1s `/proc/stat` sample) | PASS `<50` / WARN `<80` / FAIL |
| `sudo-logging` | medium | 5.3 4.2 | sudo logs to syslog (not `!syslog`) | PASS: logging / — / FAIL: `!syslog` (WARN: unreadable) |
| `password-policy` | medium | 5.4.1 | pwquality `minlen>=12` (+ `.d`, PAM fallback) | PASS: `>=12` / WARN: PAM present, minlen unknown / FAIL: weak/none |
| `suid-files` | high | 6.1 | SUID-root files not owned by a package (`-xdev`) | PASS: all owned / WARN: no package mgr / FAIL: unowned found |

Thresholds for the threshold-based checks are tunable per host role via
`--policy` — see [`config/`](../config).

## Fields in machine output

- `id`, `test`, `status`, `severity`, `message`, `remediation` — per check.
- `cis` — array of indicative CIS control references (may be empty).
- `evidence` — the concrete observed value (e.g. `PermitRootLogin=yes`,
  `usage=85%`), for audit trails.
- `ignored` — `true` when excluded from the exit code via `--ignore`.
