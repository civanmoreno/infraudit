# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.2.0] - 2026-03-27

### Added
- **GitHub Action** (`action/action.yml`): official action for CI/CD with two execution modes — `local` (audit the runner) and `ssh` (audit remote server via SSH). Auto binary download, remote architecture detection, SARIF upload for GitHub Code Scanning, `min-score` gate, job summary with metrics
- **Homebrew formula** (`Formula/infraudit.rb`): `brew tap civanmoreno/tap ... && brew install infraudit` with amd64/arm64 support
- **`scripts/update-formula.sh`**: auto-updates SHA256 and version from the latest release
- **~110 new tests**: coverage from 36% to 47.5%, eliminating all packages with 0% coverage
- Tests for boot (55%), backup (52%), malware (44%), nfs (71%), container (44%), rlimit (67%), packages (65%)
- Network expanded from 9% to 53% (SNMP, DNS, IPv6, DNSSEC, DoT, bind address)
- Services expanded from 23% to 32% (XDMCP, MTA, sudo, SSH settings)

### Changed
- 15+ source files updated to `check.P()` for test isolation via FSRoot
- RELEASING.md: added step 9 (update Homebrew formula)
- docs/output.html: GitHub Action section replaced with official action
- docs/getting-started.html: Homebrew as installation option

## [2.1.0] - 2026-03-27

### Added
- **OS Detection**: new `internal/osinfo` package that detects distro, family (Debian/RedHat/SUSE/Alpine/Arch), package manager and init system via `/etc/os-release`
- **SKIPPED status**: new status for checks that don't apply to the detected OS/init system. Excluded from scoring
- **OS info in reports**: detected OS information in console, JSON, YAML, HTML, Markdown and SARIF
- **24 checks with RequiredInit("systemd")**: BAK-001, CRON-001, FS-011, FS-012, LOG-001, LOG-002, NFS-002, NFS-004, PKG-004, SVC-001, SVC-003, SVC-007, SVC-009, SVC-010, SVC-012, SVC-013, SVC-014-027, SVC-049
- **CRYPTO-001 as RedHat-only**: annotated with `SupportedOS: ["redhat"]`
- **SVC-052 as Debian-only**: annotated with `SupportedOS: ["debian"]`
- **YAML plugin system**: custom checks in `/etc/infraudit/checks.d/*.yaml` without recompilation. 6 rule types: `file_exists`, `file_missing`, `file_contains`, `file_not_contains`, `file_perms`, `command`
- **`baseline` command**: `save`, `check`, `show`, `clear` for regression detection. Exit code 1 on regressions
- **SVC-057**: new Redis authentication check (`requirepass`)
- **Standards & Methodology**: new HTML page documenting sources (CIS, STIG, NIST), methodology and mapping to PCI-DSS, SOC 2, HIPAA, ISO 27001, FedRAMP
- **SECURITY.md**: vulnerability disclosure policy
- **CONTRIBUTING.md**: contribution guide with development patterns, commit conventions and check IDs
- **Issue templates**: bug report, new check request, feature request
- **PR template**: checklist for tests, lint, docs, CIS mapping
- **FUNDING.yml**: GitHub Sponsors enabled
- **~270 new tests**: coverage from 10.3% to 35.9% across 12 packages

### Fixed
- **SVC-052**: removed `RequiredInit("systemd")` — the check uses `PkgInstalled` which doesn't require systemd (#25)
- **baseline check**: was using `AllEntries` (with `json:"-"` tag) to compare baseline, causing all checks to appear as "new". Now uses `Entries` (#26)
- **Checks updated to `check.P()`**: 20+ check files updated to use `check.P()` for file paths, enabling test isolation via FSRoot
- **gofmt and gosec**: resolved all golangci-lint warnings in test files

### Changed
- **doctor command**: now shows detected OS, family, package manager and init system
- **Coverage CI**: now runs coverage on all packages (`./...`) instead of only core
- **Release CI**: only creates release when tag doesn't exist (prevents overwriting releases)
- **Release notes**: uses `RELEASE_NOTES.md` instead of auto-generated notes

## [2.0.0] - 2026-03-25

### Added
- 66 new checks (221 → 287 total) for complete CIS coverage
- SSH advanced: 7 checks (ClientAlive, LogLevel, UsePAM, DisableForwarding, GSSAPI, Kerberos)
- Firewall detailed: 8 checks (default deny, loopback, outbound, established, IPv6 rules)
- Kernel hardening: 10 checks (BPF, kexec, kptr_restrict, perf_event, SysRq, namespaces)
- Filesystem permissions: 17 checks (cron dirs, at/cron allow, sshd_config, gshadow)
- Logging advanced: 8 checks (journald forward, rsyslog remote, audit immutable)
- PAM advanced: 8 checks (nullok, securetty, login.defs UID/GID/UMASK/ENCRYPT)
- Services advanced: 8 checks (rpcbind, XDMCP, prelink, apport, tftp, ldap, talk, rsh)
- Remediation on 100% of all 287 checks

## [1.1.0] - 2026-03-22

### Added
- `explain` command with CIS/STIG mapping and detailed remediation
- `top` command for most critical findings
- `diff` command to compare two JSON audit reports
- `scan` command for remote auditing via SSH
- SARIF format for GitHub/GitLab integration
- `doctor` command for system readiness diagnostics
- Policy-as-code with `--enforce-policy`
- `compliance` command for CIS Benchmark reporting
- Markdown format
- Hardening Index (scoring 0-100 with A-F grades)
- Self-contained HTML report
- Shell completion
- Man page

## [1.0.0] - 2026-03-19

### Added
- 132 initial checks across 17 categories
- Output formats: console, JSON, YAML
- Server profiles (web-server, db-server, container-host, minimal)
- Configuration via JSON files (system, user, directory)
- Parallel execution with `--parallel`
- Command timeouts
- CI/CD with tests, lint, race detector, SBOM, cosign signing
