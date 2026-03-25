# infraudit — Development Plan

## Vision

Go CLI that runs directly on a Linux server to audit its security posture. Validates configurations, permissions, services, network, users, and hardening best practices according to CIS Benchmarks, STIG, and industry standards. Generates a report with findings categorized by severity.

## References

- CIS Benchmarks (Ubuntu 24.04, RHEL 9, Debian 12)
- DISA STIG for Linux
- Lynis (audit categories)
- OWASP Docker Security Cheat Sheet

## Phases

### Phase 1: Initial Scaffold ✅

- [x] Initialize Go module (`go mod init`)
- [x] Cobra dependency for CLI
- [x] `main.go` — entry point
- [x] `cmd/root.go` — root command with `--help`, `--version`
- [x] `internal/version/version.go` — version constants

### Phase 2: Audit Engine and Check Model ✅

- [x] Define `Check` interface (name, category, severity, `Run() Result`)
- [x] Check registry with autodiscovery
- [x] Result model: PASS / WARN / FAIL / ERROR with message and remediation
- [x] `infraudit audit` — runs all registered checks
- [x] `infraudit audit --category <cat>` — filter by category
- [x] `infraudit list` — list all available checks

### Phase 3: User and Authentication Checks (AUTH) ✅

- [x] SSH root login disabled (`PermitRootLogin no`)
- [x] SSH password authentication disabled (`PasswordAuthentication no`)
- [x] Users with UID 0 (only root should have it)
- [x] Users without password or with empty password
- [x] System accounts with login shell (should have `/nologin` or `/false`)
- [x] Sudoers: excessive `NOPASSWD` usage
- [x] Permissions on `/etc/passwd`, `/etc/shadow`, `/etc/group`
- [x] `su` restriction via `pam_wheel.so` (authorized group only)

### Phase 4: PAM and Password Policy Checks (PAM) ✅

- [x] Password quality via `pam_pwquality` (minlen, dcredit, ucredit, lcredit, ocredit, minclass)
- [x] Password reuse prevention (`pam_pwhistory`, `remember >= 5`)
- [x] Account lockout on failed attempts (`pam_faillock`: deny, unlock_time, fail_interval)
- [x] Correct PAM module ordering (faillock before pam_unix)
- [x] Password expiration configured (maxdays, mindays, warndays)

### Phase 5: Network and Firewall Checks (NET) ✅

- [x] Firewall active (iptables/nftables/ufw)
- [x] Unnecessary open ports (compare against configurable whitelist)
- [x] IP forwarding disabled (if not a router/gateway)
- [x] Services listening on 0.0.0.0 vs localhost
- [x] DNS resolvers configured
- [x] DNSSEC validation enabled (if running resolver)
- [x] DNS over TLS/HTTPS (systemd-resolved, unbound)
- [x] IPv6 — disabled or properly configured
- [x] SNMP v1/v2c disabled (SNMPv3 only if needed)
- [x] Default community strings removed (no `public`/`private`)
- [x] SNMP removed if unused

### Phase 6: Services and Process Checks (SVC) ✅

- [x] Insecure services running (telnet, rsh, rlogin, xinetd, etc.)
- [x] SSH: protocol version, weak ciphers, timeout configured
- [x] NTP/chrony synchronized and configured (not just running)
- [x] NTP daemon not running as root (user `_chrony` or `chrony`)
- [x] NTS (Network Time Security) enabled if possible
- [x] Time sources are trusted/authoritative
- [x] Critical services active (sshd, fail2ban/crowdsec, logging)
- [x] Processes running as root that shouldn't be
- [x] MTA configured as local-only (Postfix: `inet_interfaces = loopback-only`)
- [x] MTA is not an open relay
- [x] Mail aliases for root (forward to monitored account)
- [x] GDM/desktop environment not installed on servers
- [x] Automount disabled (autofs)

### Phase 7: Filesystem and Permission Checks (FS) ✅

- [x] Unnecessary SUID/SGID files
- [x] World-writable files outside /tmp
- [x] Missing sticky bit on directories that need it (/tmp, /var/tmp)
- [x] Sensitive partitions mounted with `noexec`, `nosuid`, `nodev`
- [x] `/dev/shm` mounted with `nodev`, `nosuid`, `noexec`
- [x] Home directory permissions (not world-readable)
- [x] Orphaned files (no owner)
- [x] Separate partitions: `/tmp`, `/var`, `/var/log`, `/var/log/audit`, `/var/tmp`, `/home`
- [x] `/tmp` on separate partition or tmpfs with `nodev`, `nosuid`, `noexec`
- [x] `/var/tmp` with `nodev`, `nosuid`, `noexec`
- [x] `tmp.mount` enabled if using systemd
- [x] Temporary file cleanup configured (`systemd-tmpfiles` or `tmpreaper`)

### Phase 8: Logging and Audit Checks (LOG) ✅

- [x] Syslog/journald active and configured
- [x] auditd installed and running
- [x] Audit rules for sensitive files (/etc/passwd, /etc/shadow, sudoers)
- [x] Log rotation configured (logrotate)
- [x] Logs not world-readable
- [x] AIDE or equivalent installed (file integrity monitoring)
- [x] AIDE database initialized
- [x] AIDE checks scheduled via cron
- [x] AIDE covers critical paths (`/bin`, `/sbin`, `/lib`, `/etc`, `/boot`)

### Phase 9: Package and Update Checks (PKG) ✅

- [x] Pending security updates
- [x] Repos configured correctly (no insecure/HTTP repos)
- [x] Kernel up to date
- [x] Automatic security updates enabled (unattended-upgrades / dnf-automatic)

### Phase 10: Kernel Hardening Checks (HARD) ✅

- [x] Login banner configured (`/etc/issue`, `/etc/issue.net`)
- [x] Core dumps disabled (sysctl + limits.conf `hard core 0`)
- [x] ASLR enabled (`kernel.randomize_va_space = 2`)
- [x] dmesg restriction (`kernel.dmesg_restrict = 1`)
- [x] ptrace restriction (`kernel.yama.ptrace_scope >= 1`)
- [x] `/proc` hardening
- [x] Swap encrypted or absent if not needed
- [x] Unnecessary kernel modules blacklisted (`cramfs`, `freevxfs`, `hfs`, `hfsplus`, `jffs2`, `squashfs`, `udf`)
- [x] USB storage disabled if not needed (`usb-storage` blacklisted)
- [x] Wireless modules disabled if not needed
- [x] Firewire/Thunderbolt DMA disabled (`firewire-core`, `thunderbolt`)
- [x] Bluetooth disabled if not needed

### Phase 11: Boot and MAC Checks (BOOT) ✅

- [x] GRUB password configured
- [x] Bootloader config permissions (`/boot/grub/grub.cfg` = `0600` root:root)
- [x] Secure Boot enabled if hardware supports it
- [x] Single-user mode requires authentication
- [x] SELinux or AppArmor installed and enabled
- [x] SELinux in `Enforcing` mode / AppArmor in `enforce` mode
- [x] No unconfined processes/profiles
- [x] Check for denials in SELinux/AppArmor logs

### Phase 12: Cron and Scheduled Job Checks (CRON) ✅

- [x] Cron daemon enabled and running
- [x] `/etc/crontab` permissions = `0600` root:root
- [x] Cron directory permissions (`/etc/cron.{hourly,daily,weekly,monthly}` = `0700`)
- [x] `/etc/cron.allow` exists and `/etc/cron.deny` removed (whitelist)
- [x] `/etc/at.allow` exists and `/etc/at.deny` removed (whitelist)
- [x] Review suspicious cron jobs (network downloads, world-writable scripts)
- [x] User crontab audit

### Phase 13: TLS/SSL and Cryptography Checks (CRYPTO) ✅

- [x] System crypto policy (not `LEGACY` on RHEL/Fedora)
- [x] Expired or soon-to-expire certificates in `/etc/ssl/certs`, `/etc/pki`
- [x] Self-signed certificates in production
- [x] TLS 1.0 and 1.1 disabled system-wide
- [x] Weak cipher suites (RC4, DES, 3DES, NULL)
- [x] Complete certificate chain
- [x] Private key permissions (`0600` or `0400`, owned by root or service user)
- [x] FIPS mode if required
- [x] No MD5/SHA1 in authentication or signing contexts

### Phase 14: Secrets and Credential Checks (SECRETS) ✅

- [x] No secrets in environment variables (`/etc/environment`, `/etc/profile.d/`, `.bashrc`)
- [x] No passwords in shell history (`.bash_history`)
- [x] No credentials in world-readable files
- [x] Credential file permissions (`.pgpass`, `.my.cnf`, `.netrc` = `0600`)

### Phase 15: Container Checks (CONTAINER) ✅

- [x] Detect if Docker/Podman is installed
- [x] Docker daemon config (`/etc/docker/daemon.json`)
- [x] Docker socket permissions (`/var/run/docker.sock`)
- [x] Containers running as root
- [x] Privileged containers (`--privileged`)
- [x] Container resource limits (CPU, memory)
- [x] Docker content trust enabled
- [x] ICC (Inter-container communication) disabled if not needed
- [x] Read-only root filesystem in containers
- [x] Docker logging driver configured
- [x] Images from trusted registries

### Phase 16: Resource Limit Checks (RLIMIT) ✅

- [x] Open files limit reasonable
- [x] Per-user process limit (`nproc`) against fork bombs
- [x] Stack size limits
- [x] No wildcard unlimited entries in `/etc/security/limits.conf`
- [x] Root filesystem disk space (alert >85%)
- [x] Space in `/var`, `/var/log`, `/tmp`
- [x] Inodes — verify no exhaustion

### Phase 17: NFS/SMB and Network Filesystem Checks (NFS) ✅

- [x] NFS exports reviewed (no world-exported, `root_squash` enabled)
- [x] NFSv3 disabled if NFSv4 available
- [x] Samba config reviewed (no guest access)
- [x] `rpcbind` disabled if NFS not in use

### Phase 18: Rootkit and Malware Checks (MALWARE) ✅

- [x] rkhunter or chkrootkit installed
- [x] Rootkit scans scheduled via cron
- [x] ClamAV installed if server handles uploads or mail
- [x] Antimalware definitions up to date

### Phase 19: Backup Checks (BACKUP) ✅

- [x] Backup schedule exists and ran recently
- [x] Backups encrypted
- [x] Backup file permissions (not world-readable)
- [x] Off-site/off-host backup (not only on the same server)

### Phase 20: Output and Reports ✅

- [x] Console output with severity
- [x] Console output with ANSI colors
- [x] `--format json` for pipeline integration
- [x] `--format yaml`
- [x] `--output <file>` export to file
- [x] Final summary: total checks, pass, warn, fail
- [x] Exit code based on severity (0 = all OK, 1 = warnings, 2 = failures)
- [x] Remediation recommendations for each failed check

### Phase 21: Configuration ✅

- [x] Config file (`/etc/infraudit/config.json` or `~/.infraudit.json`)
- [x] Allowed ports whitelist
- [x] Allowed root processes whitelist
- [x] Skip individual checks or categories (`--skip`)
- [x] Pre-built profiles: `web-server`, `db-server`, `minimal`, `container-host`
- [x] `--profile <name>` to select profile

### Phase 22: DevOps Hardening ✅

- [x] Command timeouts — `RunCmd()` with `context.WithTimeout` for all 50 `exec.Command` calls (30s default, 60s for filesystem scans)
- [x] Configurable timeout via `command_timeout` field in config JSON
- [x] Makefile with targets: build, test, lint, vet, clean, release, cover, docker
- [x] `.golangci.yml` — linters: gosec, errcheck, staticcheck, gocritic, govet, ineffassign, unused
- [x] Race detector in CI (`go test -race`)
- [x] golangci-lint in CI pipeline
- [x] Integration tests for helpers (RunCmd timeout, ServiceActive, ReadSysctl)
- [x] Unit tests for config (Load, ShouldSkip, merge, CommandTimeout)
- [x] Unit tests for report (WriteJSON, WriteYAML, WriteConsole)
- [x] Coverage: check 92.9%, config 64.3%, report 76.6%
- [x] Dockerfile — multi-stage build (golang:1.24-alpine → alpine:3.21)
- [x] Config merge — configs from all levels (system + user + directory) merged with deduplication
- [x] Parallel check execution — `--parallel N` flag with worker pool
- [x] Progress indicator — running counter on stderr
- [x] CI coverage upload (codecov)
- [x] SBOM generation (anchore/sbom-action)
- [x] Release artifact signing (cosign/Sigstore)

### Phase 23: CLI UX Improvements ✅

- [x] Auto-disable progress indicator when stderr is not a TTY (pipe-safe)
- [x] ANSI escape `\033[2K` for clean line clearing
- [x] `--quiet` / `-q` flag to suppress progress output
- [x] `--category` now supports comma-separated values (auth,network,crypto)
- [x] `--check ID` to run a single check by ID
- [x] `--severity-min` to filter displayed results (low,medium,high,critical)
- [x] `--ignore-errors` to not count errors toward exit code 2
- [x] Duration displayed in summary ("Completed in 12.3s") and JSON/YAML
- [x] `list` command: sorted by category+ID, `--category`, `--severity`, `--format json`
- [x] New `categories` subcommand with check counts and JSON output
- [x] `ParseSeverity()`, `ByCategories()`, `ByID()` added to check package

### Phase 24: HTML Report ✅

- [x] `--format html` generates a self-contained visual HTML report
- [x] Dark theme matching documentation design system
- [x] Summary dashboard with 4 metric cards and progress bar
- [x] Checks grouped by category with status badges and severity indicators
- [x] Remediation displayed inline for each finding
- [x] Responsive design (mobile + print-friendly via @media print)
- [x] Autocontenido — single .html file with embedded CSS, Google Fonts

### Phase 25: Hardening Index (Scoring) ✅

- [x] Scoring algorithm — weighted by severity: CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1, INFO=0
- [x] PASS earns full points, WARN earns half, FAIL earns zero, ERROR excluded
- [x] Score = (earned / possible) × 100, range 0–100
- [x] Letter grade: A (≥90), B (≥80), C (≥70), D (≥60), F (<60)
- [x] `Score` and `Grade` fields in `Summary` struct (JSON/YAML output)
- [x] Console output — Hardening Index with color-coded score and grade in summary box
- [x] HTML report — score circle card with grade, color-coded by rating
- [x] Unit tests for `ComputeScore` and `ScoreGrade` (all pass, all fail, mixed, errors excluded, info ignored, empty)

### Phase 26: Quality Hardening ✅

- [x] Fix: UID comparison bug — `system_shell.go` used string comparison (`uid >= "1000"`) instead of numeric, replaced with `strconv.Atoi`
- [x] Fix: `moduleBlacklisted()` — distinguished "module not found" from permission errors to avoid false positives
- [x] Fix: Certificate check — surface parse errors as warnings instead of silently swallowing, add Details with affected filenames
- [x] SUID scan expanded — added `/opt` and `/usr/local` to search paths, added `-xdev` to prevent crossing filesystem boundaries
- [x] SSH config parser — handle both `Key Value` and `Key=Value` formats
- [x] Check details — added `Details` map to SNMP, container root, privileged, resource limits, read-only rootfs, and cert expiry checks
- [x] Shared helpers — `ParsePasswd()`, `ParseShadow()`, `ParseMounts()`, `HasMountOption()` in `check/helpers.go` to reduce code duplication
- [x] Config expansion — added `allowed_suid` config field; FS-001 now respects user-defined SUID whitelist
- [x] Samba pattern matching — normalized `guest ok`, `guest_ok`, and `map to guest` parsing to handle spacing variations

### Phase 27: Code Consolidation ✅

- [x] Adopt shared helpers — `uid_zero.go`, `empty_password.go`, `system_shell.go`, `boot.go` now use `ParsePasswd()`/`ParseShadow()` instead of duplicated parsing
- [x] Adopt shared helpers — `mount_options.go`, `partitions.go`, `hardening.go` now use `ParseMounts()`/`HasMountOption()` instead of local functions
- [x] Adopt shared helpers — `crypto.go` weakHash check now uses `ParseShadow()`
- [x] Error handling — `packages.go` returns `Error` when apt/dnf commands fail instead of `Pass`
- [x] Error handling — `nfs.go` rpcbind check uses `ServiceActive()` helper instead of raw command with ignored errors
- [x] Unit tests — added `TestHasMountOption`, `TestParseMounts`, `TestParsePasswd` to `helpers_test.go`
- [x] Documentation — `docs/index.html` updated with Hardening Index feature card, HTML output mention, and score in sample output

### Phase 28: Check Validation Tests & Performance Cache ✅

- [x] Registry validation test suite — 8 tests validating all 132 registered checks:
  - No duplicate IDs, ID format (PREFIX-NNN), valid categories, valid severities
  - Non-empty fields (ID, Name, Description), all 17 categories covered
  - ID prefix matches category (AUTH-xxx → auth, NET-xxx → network, etc.)
- [x] Performance: `sync.Once` cache for `ParsePasswd()`, `ParseShadow()`, `ParseMounts()`
  - Each file read once per audit instead of 3–6 times
  - Thread-safe via `sync.Once` — safe with `--parallel`
  - `ResetCache()` available for tests

### Phase 29: Status Filter ✅

- [x] `--status` flag — filter displayed results by status (comma-separated: pass, warn, fail, error)
- [x] Summary and score always reflect the full audit (filters only affect displayed entries)
- [x] `AllEntries` field in Report struct to preserve unfiltered results for score computation
- [x] Validation of status values with clear error message

## Check Categories

| Category | Prefix | Description |
|----------|--------|-------------|
| `auth` | AUTH- | Users, SSH, sudoers, passwords |
| `pam` | PAM- | PAM, password quality, lockout |
| `network` | NET- | Firewall, ports, interfaces, DNS, SNMP |
| `services` | SVC- | Services, processes, daemons, NTP, MTA |
| `filesystem` | FS- | Permissions, SUID, partitions, ownership, /tmp, /dev/shm |
| `logging` | LOG- | Syslog, auditd, rotation, AIDE/integrity |
| `packages` | PKG- | Updates, repos, kernel |
| `hardening` | HARD- | Kernel params, ASLR, ptrace, core dumps, modules |
| `boot` | BOOT- | GRUB, Secure Boot, SELinux/AppArmor |
| `cron` | CRON- | Cron/at jobs, permissions, whitelist |
| `crypto` | CRYPTO- | TLS/SSL, certificates, ciphers, FIPS |
| `secrets` | SEC- | Exposed credentials, history, env vars |
| `container` | CTR- | Docker/Podman, images, runtime security |
| `rlimit` | RLIM- | Resource limits, disk, inodes |
| `nfs` | NFS- | NFS exports, Samba, rpcbind |
| `malware` | MAL- | Rootkits, antimalware, integrity |
| `backup` | BAK- | Backups, encryption, off-site |

## Severity Model

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Exploitable vulnerability, immediate action |
| `HIGH` | Significant risk, fix soon |
| `MEDIUM` | Best practice not applied |
| `LOW` | Recommended improvement, low risk |
| `INFO` | Informational, no action needed |

## Project Structure

```
infraudit/
├── .claude/commands/       # Claude Code skills
├── .github/workflows/      # CI/CD
├── docs/                   # Documentation (GitHub Pages)
├── cmd/
│   ├── root.go             # Root command
│   ├── audit.go            # Audit subcommand
│   └── list.go             # List subcommand
├── internal/
│   ├── version/            # Version info
│   ├── check/              # Check interface, Result, Registry, helpers
│   ├── config/             # Configuration and profiles
│   ├── checks/
│   │   ├── auth/           # AUTH- checks
│   │   ├── pam/            # PAM- checks
│   │   ├── network/        # NET- checks
│   │   ├── services/       # SVC- checks
│   │   ├── filesystem/     # FS- checks
│   │   ├── logging/        # LOG- checks
│   │   ├── packages/       # PKG- checks
│   │   ├── hardening/      # HARD- checks
│   │   ├── boot/           # BOOT- checks
│   │   ├── cron/           # CRON- checks
│   │   ├── crypto/         # CRYPTO- checks
│   │   ├── secrets/        # SEC- checks
│   │   ├── container/      # CTR- checks
│   │   ├── rlimit/         # RLIM- checks
│   │   ├── nfs/            # NFS- checks
│   │   ├── malware/        # MAL- checks
│   │   └── backup/         # BAK- checks
│   └── report/             # Report formatting and output
├── install.sh              # Install script
├── main.go
├── go.mod / go.sum
├── Makefile                # Build, test, lint, release targets
├── Dockerfile              # Multi-stage build
├── .golangci.yml           # Linter configuration
├── PLAN.md
├── README.md
└── LICENSE
```
