# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2026-07-13

Enterprise/operational output and configurability. All additive.

### Added
- **Severity + remediation per check**: every result now includes a `severity`
  (`critical`/`high`/`medium`/`low`/`info`, the control's inherent risk weight)
  and a `remediation` string, from a pure, unit-tested `meta_for()` table.
- **`not_applicable` (NA) status**: checks that don't apply to the host (e.g. apt
  checks on a non-Debian system) report `NA` instead of a misleading `WARN`. `NA`
  never affects the exit code; the summary gains a `not_applicable` count.
- **Tool provenance in JSON**: a top-level `tool { name, version, commit }`.
  Released artifacts have the real commit stamped in by the release workflow.
- **Policy files (`--policy FILE`)**: tune thresholds (failed logins, running
  services, public ports, disk/mem/cpu) per host role without editing the script.
  Parsed safely (`KEY=INTEGER`, never sourced); unknown keys/values are rejected.
  Ships example + `web`/`database`/`bastion` role policies under `config/`.
- **Scheduling examples**: systemd service+timer and cron under `examples/`, with
  a deployment guide at `docs/deployment.md`.
- New tests: `meta_for` coverage, `load_policy` parsing/rejection, and JSON
  severity/remediation/tool assertions. Schema + sample report updated.

## [3.1.0] - 2026-07-13

Safety-hardening follow-up (three high-priority fixes).

### Security
- **Stronger report-file creation**: `safe_open_report()` now refuses a
  world-writable parent directory that lacks the sticky bit (another user could
  swap the path), keeps the atomic `noclobber` open, and documents its
  `O_EXCL`/`O_NOFOLLOW`-equivalent guarantee. New Bats tests cover unsafe
  (world-writable, non-sticky) and safe (sticky) parents.
- **Hardened release publishing**: top-level workflow permissions are now
  `contents: read`, with `contents/id-token/attestations: write` granted only to
  the release job; the job runs in a protected `release` environment (gate
  publishers via repo settings). The `SHA256SUMS` manifest is attested
  (signed) alongside the script.

### Changed
- **External public-IP lookup is now opt-in.** The audit makes no network calls
  by default; pass `--public-ip` to enable the `api.ipify.org` lookup.
  `--no-public-ip` is retained (now the default) for backward compatibility.
  Safer for air-gapped and compliance-sensitive environments.

## [3.0.0] - 2026-07-13

Follow-up hardening from a second review pass. **Breaking:** each JSON result
now carries a stable `id` field (schema updated).

### Security
- **Race-free report open** — `safe_open_report()` now creates the report with a
  single atomic `O_CREAT|O_EXCL` open (via `noclobber`) that fails without
  writing if the path is swapped for a file or symlink after the pre-checks
  (TOCTOU). `umask 077` yields mode `0600`, removing the post-open
  `chmod`-by-name that previously re-opened the path.

### Added
- **Stable check IDs**: every JSON result includes a machine-readable `id`
  (kebab-case, e.g. `ssh-root-login`, `firewall`, `suid-files`) that is decoupled
  from the human name/message. Schema (`docs/vps-audit.schema.json`) updated to
  require and pattern-validate `id`.
- **Release signing/attestation**: the release workflow now produces a keyless
  (Sigstore) build-provenance attestation for `vps-audit.sh` and `SHA256SUMS`,
  verifiable with `gh attestation verify`.
- **Mocked host-state tests** (`tests/bats/host-state.bats`): the script is now
  sourceable (guarded `main`), and decision logic lives in pure `eval_*`
  functions that are unit-tested against mocked states.

### Changed
- Refactored the audit body into a guarded `main()` plus pure evaluators; no
  change to check outcomes on a real host.
- README documents attestation verification in the install steps.

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

[3.2.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.2.0
[3.1.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.1.0
[3.0.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.0.0
[2.1.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v2.1.0
[2.0.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v2.0.0
