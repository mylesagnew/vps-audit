# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| 2.x     | ✅        |
| < 2.0   | ❌        |

## Reporting a Vulnerability

This tool runs with root privileges, so bugs in it can have real impact
(false assurance, information disclosure in the report file, or unexpected
command execution). Please report suspected vulnerabilities privately.

- **Preferred:** open a [GitHub Security Advisory](https://github.com/mylesagnew/vps-audit/security/advisories/new)
  so the discussion stays private until a fix is released.
- **Alternative:** email the maintainer at `myles.agnew@gmail.com`.

Please include:

- the script version (`git rev-parse HEAD` or the release tag),
- the OS/distribution and version,
- a description of the issue and, if possible, steps to reproduce.

Please **do not** open a public issue for security-sensitive reports.

## Disclosure Expectations

- Acknowledgement within **7 days**.
- A fix or mitigation plan within **30 days** where feasible.
- Credit in the changelog for the first reporter, unless you prefer to remain anonymous.

## Scope Notes

- The generated report (`vps-audit-report-*.txt`) contains reconnaissance-grade
  data (hostname, public IP, open ports, service inventory). It is written with
  `chmod 600`; keep it protected and do not commit it (`.gitignore` already
  excludes it).
- This script is an aid, not a substitute for a professional security audit.
