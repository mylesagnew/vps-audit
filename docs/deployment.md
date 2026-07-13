# Recurring & scheduled runs

Run the audit on a schedule and keep the reports somewhere root-only. Example
unit/cron files live in [`examples/`](../examples).

## Prerequisites

Install the verified script to a stable path and create a root-only report dir:

```bash
sudo install -m 0755 vps-audit.sh /usr/local/bin/vps-audit.sh
sudo install -d -m 0700 -o root -g root /var/log/vps-audit
```

## systemd timer (recommended)

```bash
sudo cp examples/systemd/vps-audit.service /etc/systemd/system/
sudo cp examples/systemd/vps-audit.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vps-audit.timer

# See when it next runs / last ran:
systemctl list-timers vps-audit.timer
# Read the last run's output:
journalctl -u vps-audit.service --no-pager | tail -n 40
```

The service runs `vps-audit.sh --strict` from `/var/log/vps-audit`, so each run
writes its own timestamped `vps-audit-report-<TIMESTAMP>.txt` (mode `0600`).
Load a role policy by editing `ExecStart` to add `--policy /etc/vps-audit.conf`.

> `Type=oneshot` audits exit non-zero on findings; the unit uses
> `SuccessExitStatus=0 1` so a finding doesn't mark the unit failed. Remove that
> line if you'd rather surface findings as unit failures for alerting.

## cron

```bash
sudo cp examples/cron/vps-audit.cron /etc/cron.d/vps-audit
```

Weekly run (Sun 03:30) as root. See the file for a `--json` variant that writes
one JSON document per run for SIEM/log ingestion.

## Per-role thresholds

Pick a policy for the host's role and install it:

```bash
sudo install -m 0644 config/roles/web.conf /etc/vps-audit.conf   # or database.conf / bastion.conf
```

Then pass `--policy /etc/vps-audit.conf` in the service/cron command. See
[`config/vps-audit.example.conf`](../config/vps-audit.example.conf) for every
tunable key and its default.
