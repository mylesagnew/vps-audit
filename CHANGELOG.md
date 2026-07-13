# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2026-07-13

Stability milestone. This release **consolidates** the 2.x/3.x work into a
maintained 4.0 line; it contains **no new features and no new breaking changes**
versus 3.6.0 — the major bump marks the tool's maturity and API stability.

Since the 1.x upstream, `vps-audit` gained: trustworthy checks (no false
PASS/FAIL), hardened root execution and race-free reporting, a sourceable
pure-function architecture with a Bats + multi-distro container test suite,
stable check IDs with severity/remediation/evidence and indicative CIS mapping,
five output formats (text/JSON/JSONL/SARIF/Markdown/HTML), policy files,
`--ignore`/`--fail-on`, baseline drift detection, opt-in webhooks, gated
dry-run-by-default remediation, and checksum-verified, Sigstore-attested releases.

### Changed
- README rewritten with status badges, a capability feature matrix, and a
  copy-paste quick start.
- Version bumped to 4.0.0.

## [3.6.0] - 2026-07-13

Optional integrations — both opt-in and safe by default.

### Added
- **Webhook output (`--webhook URL`)**: POSTs a compact JSON payload (`tool`,
  `hostname`, `summary`, and WARN/FAIL findings only) to a user-supplied endpoint
  on completion. Deliberately **omits** evidence strings, public IP, port lists,
  and SUID paths to minimise data egress. `--webhook-on fail` restricts to runs
  with FAILs. Logs the HTTP status to stderr; never affects stdout or exit code.
- **Gated auto-remediation (`--remediate` / `--remediate-apply`)**: off by
  default and **dry-run by default**. Applies only a small allowlist of
  reversible hardening fixes (`PermitRootLogin no`, `PasswordAuthentication no`,
  enable `ufw`, install `unattended-upgrades`) and only to `FAIL`ing checks.
  Safeguards: applying requires `--remediate-apply` **and** root; sshd changes are
  backed up and validated with `sshd -t` before reload; `ufw` is enabled only
  **after** allowing the current SSH port (no lock-out). `--remediate-only ID`
  limits scope. All remediation activity logs to stderr, separate from output.
- Unit tests for the webhook payload and remediation planning; the container
  matrix now also exercises `--remediate` dry-run on every distro.

## [3.5.0] - 2026-07-13

Drift detection and multi-distro CI. Additive.

### Added
- **Baseline drift (`--baseline FILE`)**: compare a run against a prior
  `--json`/`--jsonl` result by check `id`. Output gains a `drift` object —
  `regressed`/`improved` (`{id, from, to}`), `new`, `removed` — surfaced in JSON,
  text, and Markdown reports. `--fail-on-drift` makes any regression a non-zero
  exit. Baseline parsing is dependency-free (no jq); pure functions
  (`status_rank`, `baseline_status`, `baseline_ids`, `compute_drift`) with unit
  tests.
- **Container test matrix** (`.github/workflows/container-tests.yml`): runs the
  full audit inside real **Ubuntu 24.04 / Debian 12 / Rocky Linux 9** containers
  across all output modes plus a self-compare baseline, catching distro-specific
  regressions (e.g. dpkg-less hosts → `NA`, differing `ss`/`free`).

### Changed
- Schema adds an optional top-level `drift` object (present only with `--baseline`).

## [3.4.0] - 2026-07-13

Reporting and compliance evidence. Additive.

### Added
- **Markdown (`--markdown`/`--md`) and HTML (`--html`) reports** rendered from the
  same results — summary + a status/severity/check/finding/CIS/remediation table.
  HTML is self-contained (inline CSS, no external assets) and HTML-escaped.
- **CIS mapping**: each JSON result gains a `cis` array of *indicative* CIS
  Distribution Independent Linux Benchmark references (guidance, not certified).
- **Evidence field**: each result gains an `evidence` string capturing the
  concrete observed value (e.g. `PermitRootLogin=yes`, `usage=85%`) for audit trails.
- **`docs/checks.md`**: per-check rationale — what/why, PASS/WARN/FAIL/NA criteria,
  severity, and CIS mapping for every check id.
- Unit tests for `cis_for`, `json_array_from_list`, `html_escape`, and the
  Markdown/HTML emitters.

### Changed
- Schema updated: results now require `cis` (array) and `evidence` (string).

## [3.3.0] - 2026-07-13

SIEM-friendly output formats and policy exceptions. Additive.

### Added
- **JSONL output (`--jsonl`)**: one self-contained JSON object per result line
  (hostname/timestamp inlined) for SIEM/log ingestion.
- **SARIF output (`--sarif`)**: SARIF 2.1.0 for the GitHub code-scanning /
  Security tab. `FAIL`→error, `WARN`→warning, `PASS`→note, `NA`→none; `--ignore`d
  checks carry a `suppressions` entry.
- **Policy exceptions**: `--ignore ID[,ID]` excludes checks from the exit code
  (still reported, marked `"ignored": true`); `--fail-on ID[,ID]` forces a
  non-zero exit if the named ids are `FAIL`/`WARN`. Both repeat.
- New `ignored` boolean on every JSON result (schema updated).

### Changed
- Results are stored in parallel arrays and rendered by dedicated `emit_json` /
  `emit_jsonl` / `emit_sarif` functions from one source of truth.
- The port classifier and SUID package-ownership check are extracted into pure
  `ports_summary` / `classify_listen_addr` / `count_unowned` functions, now
  covered by isolated unit tests (`tests/bats/parsers.bats`) including IPv6
  brackets, `*:port`, and dual-stack edge cases.

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

[4.0.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v4.0.0
[3.6.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.6.0
[3.5.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.5.0
[3.4.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.4.0
[3.3.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.3.0
[3.2.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.2.0
[3.1.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.1.0
[3.0.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v3.0.0
[2.1.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v2.1.0
[2.0.0]: https://github.com/mylesagnew/vps-audit/releases/tag/v2.0.0
