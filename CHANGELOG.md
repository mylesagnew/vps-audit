# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-07-12

Hardening release addressing an independent Principal SecDevOps review, plus
repository restructure, a test suite, and supply-chain-safe CI/releases.

### Security
- **Root-run PATH hardening**: `PATH`/`IFS` are pinned before any command runs,
  so a poisoned environment cannot execute attacker-controlled binaries as root.
- **Safe report-file handling**: `--output` now refuses to follow symlinks or
  overwrite existing/non-regular files, and validates the parent directory. The
  report is opened once on a dedicated file descriptor. Prevents a root run from
  clobbering arbitrary files.

### Added
- `--no-public-ip` to skip the external `api.ipify.org` lookup (offline mode).
- Bats test suite (`tests/bats/`): argument parsing, output-file safety, and the
  JSON contract.
- CI jobs: `actionlint` (workflow lint) and `bats` (tests).
- Supply-chain-safe release workflow (`.github/workflows/release.yml`) that
  publishes `vps-audit.sh` + `SHA256SUMS` and release notes on tag push.
- `.github/dependabot.yml` for weekly GitHub Actions updates.
- JSON Schema (`docs/vps-audit.schema.json`) and a sample report
  (`docs/sample-report.md`).

### Changed
- **Repository restructure**: the script now lives at `scripts/vps-audit.sh`
  (was repo root); the screenshot moved to `docs/`.
- CI is now supply-chain hardened: third-party actions are pinned to commit
  SHAs, the `shfmt` and `actionlint` downloads are SHA256-verified, and runners
  are pinned to `ubuntu-24.04`.
- README rewritten with step-by-step, checksum-verified release installation and
  a development/testing section.

## [2.0.0] - 2026-07-11

Major correctness and automation overhaul. Several checks previously returned
misleading verdicts; this release fixes them and makes the output usable as a
CI/CD gate. **Breaking:** the script now exits non-zero when checks fail.

### Fixed
- **Failed logins**: the journald path was grepping a literal filename string
  and always returned `0`; it now actually runs `journalctl` and also reads
  rotated `auth.log`/`secure` files.
- **Firewall**: the iptables check matched the always-present `Chain INPUT`
  line and passed on wide-open hosts. It now inspects the `INPUT` policy / rule
  count, and nftables now requires an input hook with a drop/reject policy.
- **SUID files**: the scan whitelisted entire `bin` directories (hiding
  attacker-planted binaries). It now runs bounded (`-xdev`) and verifies every
  SUID binary against the package database (`dpkg`/`rpm`).
- **Open ports**: now parses the bind address so loopback-only services are no
  longer reported as internet-facing.
- **Sudo logging**: syslog is treated as the secure default instead of a false
  `FAIL`.
- **Password policy**: comment-aware, requires `minlen >= 12`, and checks
  `pwquality.conf.d/` plus a PAM fallback.
- **SSH**: configuration is read from the effective `sshd -T` output rather
  than brittle grepping of `sshd_config`.
- **System Updates**: distinguishes **security** updates (FAIL) from
  non-security updates (WARN) instead of mislabelling everything as security.
- **CPU usage**: sampled from `/proc/stat` over 1s (accurate, locale-independent)
  instead of `top -bn1`, which reported the since-boot average.

### Added
- `--json` machine-readable output.
- `--strict` flag (exit non-zero on `WARN` as well as `FAIL`).
- `-o, --output FILE` to set the report path; `-h, --help`.
- PASS/WARN/FAIL counters, a summary line, and CI/CD-friendly exit codes
  (`0` clean, `1` findings, `2` usage error).
- Lint CI (`.github/workflows/lint.yml`): ShellCheck, shfmt, and a smoke test.
- `SECURITY.md` disclosure policy and this changelog.

### Changed
- Report file is created with `umask 077` and `chmod 600`.
- Colour codes are suppressed when output is not a TTY or when `--json` is used.
- Network IP lookup uses `--max-time 5`.
- Running-services thresholds relaxed (PASS <35, WARN <60) to reduce false
  positives on stock systemd hosts.
- Corrected repository attribution (fork of `vernu/vps-audit`, maintained by
  `mylesagnew`).

[2.1.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v2.1.0
[2.0.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v2.0.0
