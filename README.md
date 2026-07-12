# VPS Security Audit Script

A comprehensive Bash script for auditing the security and performance of your VPS (Virtual Private Server). This tool performs various security checks and provides a detailed report with recommendations for improvements.

![Sample Output](./docs/screenshot.png)

## Features

### Security Checks

- SSH Configuration (read from the effective `sshd -T` config)
  - Root login status
  - Password authentication
  - Non-default port usage
- Firewall Status (UFW / firewalld / nftables / iptables, policy-aware)
- Intrusion Prevention (Fail2ban or CrowdSec, host or Docker container)
- Failed Login Attempts (auth.log/secure with rotation, or journald)
- System Updates Status (security vs. non-security)
- Running Services Analysis
- Open Ports Detection (internet-facing vs. loopback)
- Sudo Logging Configuration
- Password Policy Enforcement
- SUID Files Detection (verified against the package database)

### Output

- Human-readable coloured console output + timestamped report file
- Machine-readable JSON via `--json`
- CI/CD-friendly exit codes (see [Usage](#usage))

### Performance Monitoring

- Disk Space Usage
- Memory Usage
- CPU Usage
- Active Internet Connections

## Requirements

- Ubuntu/Debian-based Linux system
- Root access or sudo privileges
- Basic packages (most are pre-installed):
  - ufw
  - systemd
  - netstat
  - grep
  - awk

## Installation

> Because this script runs as **root**, install it from a **tagged release and
> verify the checksum** before running. Do not pipe an unpinned script from
> `main` straight into a root shell.

### Recommended: install a verified release

1. Pick the version you want to install:

   ```bash
   VERSION=v2.1.0
   ```

2. Download the script and its checksum file from that release:

   ```bash
   curl -fsSLO "https://github.com/mylesagnew/vps-audit/releases/download/${VERSION}/vps-audit.sh"
   curl -fsSLO "https://github.com/mylesagnew/vps-audit/releases/download/${VERSION}/SHA256SUMS"
   ```

3. Verify the download matches the published checksum (this must print `OK`):

   ```bash
   sha256sum -c SHA256SUMS --ignore-missing
   ```

4. Make it executable:

   ```bash
   chmod +x vps-audit.sh
   ```

### Alternative: clone the repository

For development or the latest unreleased code:

```bash
git clone https://github.com/mylesagnew/vps-audit.git
cd vps-audit
chmod +x scripts/vps-audit.sh
```

The script lives at `scripts/vps-audit.sh` in the repository. The examples below
assume the release layout (`./vps-audit.sh`); adjust the path if you cloned.

## Usage

1. Run the script with root privileges:

   ```bash
   sudo ./vps-audit.sh
   ```

2. Read the real-time, colour-coded results in your terminal:
   - 🟢 `[PASS]` — check passed
   - 🟡 `[WARN]` — potential issue, review it
   - 🔴 `[FAIL]` — critical issue, fix it

3. Review the saved report. By default it is written to
   `vps-audit-report-<TIMESTAMP>.txt` in the current directory with `chmod 600`
   permissions. (`--output` refuses to follow symlinks or overwrite an existing
   file.)

### Common invocations

```bash
# Standard audit (human-readable report):
sudo ./vps-audit.sh

# Skip the external public-IP lookup (fully offline):
sudo ./vps-audit.sh --no-public-ip

# Machine-readable output for automation:
sudo ./vps-audit.sh --json > audit.json

# Write the report to a specific path:
sudo ./vps-audit.sh -o /var/log/vps-audit.txt
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Emit machine-readable JSON to stdout (suppresses the coloured UI). Validates against [`docs/vps-audit.schema.json`](docs/vps-audit.schema.json). |
| `--strict` | Exit non-zero on `WARN` as well as `FAIL`. |
| `--no-public-ip` | Skip the external public-IP lookup (`api.ipify.org`). |
| `-o, --output FILE` | Write the report to `FILE`. Refuses symlinks and will not overwrite an existing file. |
| `-h, --help` | Show help and exit. |

### Exit codes (for CI/CD gating)

| Code | Meaning |
|------|---------|
| `0` | No `FAIL` findings (and, unless `--strict`, `WARN` is allowed). |
| `1` | One or more `FAIL` findings (or any `WARN` under `--strict`). |
| `2` | Usage error (unknown flag / missing argument / unsafe `--output`). |

Example pipeline step that fails the build on any `FAIL` or `WARN`:

```bash
sudo ./vps-audit.sh --json --strict > audit.json
```

## Output Format

The script provides two types of output:

1. Real-time console output with color coding:

```
[PASS] SSH Root Login - Root login is properly disabled in SSH configuration
[WARN] SSH Port - Using default port 22 - consider changing to a non-standard port
[FAIL] Firewall Status - UFW firewall is not active - your system is exposed
```

2. A detailed report file containing:
   - All check results
   - Specific recommendations for failed checks
   - System resource usage statistics
   - Timestamp of the audit

## Thresholds

### Resource Usage Thresholds

- PASS: < 50% usage
- WARN: 50-80% usage
- FAIL: > 80% usage

### Security Thresholds

- Failed Logins:
  - PASS: < 10 attempts
  - WARN: 10-50 attempts
  - FAIL: > 50 attempts
- Running Services:
  - PASS: < 35 services
  - WARN: 35-60 services
  - FAIL: > 60 services
- Open Ports (counts **internet-facing** ports only; loopback is excluded):
  - PASS: < 3 public ports
  - WARN: 3-4 public ports
  - FAIL: >= 5 public ports
- System Updates:
  - PASS: no pending updates
  - WARN: non-security updates pending
  - FAIL: one or more **security** updates pending

## Customization

You can modify the thresholds by editing the following variables in the script:

- Resource usage thresholds
- Failed login attempt thresholds
- Service count thresholds
- Open port thresholds

## Best Practices

1. Run the audit regularly (e.g., weekly) to maintain security
2. Review the generated report thoroughly
3. Address any FAIL status immediately
4. Investigate WARN status during maintenance
5. Keep the script updated with your security policies

## Limitations

- Designed for Debian/Ubuntu-based systems
- Requires root/sudo access
- Some checks may need customization for specific environments
- Not a replacement for professional security audit

## Development

The repository is laid out as:

```
.
├── scripts/vps-audit.sh          # the audit script
├── tests/bats/                   # Bats test suite
├── docs/                         # screenshot, sample report, JSON schema
└── .github/workflows/lint.yml    # ShellCheck + shfmt + Bats CI
```

To run the checks locally:

1. Install the tooling:

   ```bash
   sudo apt-get install -y shellcheck bats
   # shfmt: https://github.com/mvdan/sh/releases
   ```

2. Lint and format-check the script:

   ```bash
   shellcheck -S style scripts/vps-audit.sh
   shfmt -d -i 4 -ci -bn scripts/vps-audit.sh
   ```

3. Run the test suite:

   ```bash
   bats tests/bats
   ```

## Contributing

Feel free to submit issues and enhancement requests! Please run the checks in
[Development](#development) before opening a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Notice

While this script helps identify common security issues, it should not be your only security measure. Always:

- Keep your system updated
- Monitor logs regularly
- Follow security best practices
- Consider professional security audits for critical systems

## Support

For support, please:

1. Check the existing issues
2. Create a new issue with detailed information
3. Provide the output of the script and your system information

Stay secure! 🔒
