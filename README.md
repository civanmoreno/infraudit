# infraudit

Linux server security auditing from the command line.

A single binary you drop on any Linux server to audit its security posture. Validates users, SSH, firewall, permissions, kernel hardening, containers, certificates, and 132 checks based on CIS Benchmarks, DISA STIG, and industry best practices.

## Install

```bash
# Automatic (detects architecture)
curl -sL https://raw.githubusercontent.com/civanmoreno/infraudit/main/install.sh | sh

# Or download manually
curl -sLO https://github.com/civanmoreno/infraudit/releases/latest/download/infraudit-linux-amd64
chmod +x infraudit-linux-amd64 && sudo mv infraudit-linux-amd64 /usr/local/bin/infraudit
```

### Build from source

```bash
git clone https://github.com/civanmoreno/infraudit.git
cd infraudit
go build -o infraudit .
```

## Usage

```bash
# Full audit (requires root for most checks)
sudo infraudit audit

# Audit a specific category
sudo infraudit audit --category auth

# Use a server profile
sudo infraudit audit --profile web-server

# Skip specific checks
sudo infraudit audit --skip HARD-007,SVC-012

# Export as JSON
sudo infraudit audit --format json --output report.json

# Export as YAML
sudo infraudit audit --format yaml --output report.yaml

# List all available checks
infraudit list
```

## Commands

| Command | Description |
|---------|-------------|
| `infraudit audit` | Run security checks and generate a report |
| `infraudit list` | Show all available checks |
| `infraudit completion` | Generate shell autocompletion (bash, zsh, fish) |

## Audit flags

| Flag | Default | Description |
|------|---------|-------------|
| `--category` | *(all)* | Run checks for a single category |
| `--format` | `console` | Output format: `console`, `json`, `yaml` |
| `--output` | *(stdout)* | Write report to file |
| `--profile` | *(none)* | Server profile: `web-server`, `db-server`, `container-host`, `minimal` |
| `--skip` | *(none)* | Comma-separated check IDs to skip |

## Categories

infraudit organizes 132 checks into 17 categories:

| Category | Prefix | Checks | Description |
|----------|--------|--------|-------------|
| `auth` | AUTH- | 8 | Users, SSH, sudoers, passwords |
| `pam` | PAM- | 5 | Password quality, lockout, expiration |
| `network` | NET- | 11 | Firewall, ports, DNS, SNMP |
| `services` | SVC- | 13 | Daemons, NTP, MTA, desktop |
| `filesystem` | FS- | 12 | Permissions, SUID, partitions |
| `logging` | LOG- | 9 | Syslog, auditd, AIDE |
| `packages` | PKG- | 4 | Updates, repos, kernel |
| `hardening` | HARD- | 12 | Kernel params, ASLR, modules |
| `boot` | BOOT- | 8 | GRUB, Secure Boot, SELinux/AppArmor |
| `cron` | CRON- | 7 | Cron/at permissions, job review |
| `crypto` | CRYPTO- | 9 | TLS, certificates, ciphers |
| `secrets` | SEC- | 4 | Exposed credentials, history |
| `container` | CTR- | 11 | Docker/Podman security |
| `rlimit` | RLIM- | 7 | Resource limits, disk, inodes |
| `nfs` | NFS- | 4 | NFS exports, Samba, rpcbind |
| `malware` | MAL- | 4 | Rootkits, antimalware |
| `backup` | BAK- | 4 | Backups, encryption, off-site |

## Severity levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Exploitable vulnerability — immediate action required |
| **HIGH** | Significant risk — fix soon |
| **MEDIUM** | Best practice not applied |
| **LOW** | Recommended improvement, low risk |
| **INFO** | Informational, no action needed |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | Warnings found (no failures) |
| `2` | Failures or errors found |

Use exit codes in CI/CD pipelines to gate deployments:

```bash
sudo infraudit audit --format json --output report.json
if [ $? -eq 2 ]; then
    echo "Security failures found — blocking deployment"
    exit 1
fi
```

## Server profiles

Profiles skip categories not relevant to your server role:

| Profile | Skips | Allowed Ports |
|---------|-------|---------------|
| `web-server` | container, nfs | 22, 80, 443 |
| `db-server` | container, nfs | 22, 3306, 5432, 6379, 27017 |
| `container-host` | nfs | 22, 80, 443, 2376 |
| `minimal` | container, nfs, malware, backup | 22 |

## Configuration

Create a JSON config file for persistent settings:

```jsonc
// ~/.infraudit.json
{
  "skip": ["HARD-007", "SVC-012"],
  "skip_categories": ["container", "nfs"],
  "allowed_ports": [22, 80, 443],
  "allowed_root_processes": ["sshd", "nginx", "fail2ban"]
}
```

Config file locations (first found wins):

1. `/etc/infraudit/config.json` — system-wide
2. `~/.infraudit.json` — user-level
3. `./.infraudit.json` — directory-level

## Output formats

**Console** — colored, grouped by category, sorted by severity:

```
  infraudit v0.1.0 — Security Audit Report
  ────────────────────────────────────────────

  AUTH — Users & Authentication   5 passed  2 warn  1 fail
  ──────────────────────────────────────────────────────────
  ✗  FAIL   AUTH-001   CRITICAL  PermitRootLogin is set to 'yes'
       ↳ Set 'PermitRootLogin no' in /etc/ssh/sshd_config
  !  WARN   AUTH-006   HIGH      Found 2 NOPASSWD entries in sudoers
       ↳ Review NOPASSWD entries and remove unnecessary ones
  ✓  PASS   AUTH-003   CRITICAL  Only root has UID 0
  ✓  PASS   AUTH-007   HIGH      Permissions correct

  ══════════════════════════════════════════════════════════
  SUMMARY
  ████████████████████████████████████████  5/8 checks
  ✓ 5 Passed    ! 2 Warnings    ✗ 1 Failures    0 Errors
```

**JSON** — for CI/CD, monitoring, and automation:

```bash
sudo infraudit audit --format json --output report.json
```

**YAML** — for config management and GitOps:

```bash
sudo infraudit audit --format yaml --output report.yaml
```

## Standards coverage

| Standard | Coverage |
|----------|----------|
| CIS Benchmark Level 1 | ~90% of applicable controls |
| CIS Benchmark Level 2 | ~70% of applicable controls |
| DISA STIG | Key findings covered |
| Lynis categories | All major categories mapped |

## Documentation

Full documentation available at the [project docs](https://civanmoreno.github.io/infraudit/):

- [Getting Started](https://civanmoreno.github.io/infraudit/getting-started.html)
- [Checks Reference](https://civanmoreno.github.io/infraudit/checks.html) — detailed description and security impact of each check
- [Configuration](https://civanmoreno.github.io/infraudit/configuration.html) — CLI flags, config files, profiles
- [Output & Reports](https://civanmoreno.github.io/infraudit/output.html) — format details and CI/CD integration
- [Architecture](https://civanmoreno.github.io/infraudit/architecture.html)

## License

MIT
