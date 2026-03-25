<p align="center">
  <img src="https://img.shields.io/badge/checks-132-34d399?style=flat-square&logo=checkmarx&logoColor=white" alt="132 checks">
  <img src="https://img.shields.io/badge/categories-17-60a5fa?style=flat-square" alt="17 categories">
  <img src="https://img.shields.io/badge/go-1.24+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.24+">
  <img src="https://img.shields.io/badge/license-BSL--1.1-yellow?style=flat-square" alt="BSL 1.1 License">
  <img src="https://img.shields.io/github/v/release/civanmoreno/infraudit?style=flat-square&color=fbbf24" alt="Release">
</p>

# infraudit

> Linux server security auditing from the command line.

A single binary you drop on any Linux server to audit its security posture. No dependencies, no agents, no runtime — just copy and run. Validates **132 checks** across **17 categories** based on **CIS Benchmarks**, **DISA STIG**, and industry best practices.

<br>

📖 **[Full Documentation](https://civanmoreno.github.io/infraudit/)** · 📋 **[Checks Reference](https://civanmoreno.github.io/infraudit/checks.html)** · ⚙️ **[Configuration Guide](https://civanmoreno.github.io/infraudit/configuration.html)**

---

## ⚡ Quick Start

```bash
# Install (detects architecture automatically)
curl -sL https://raw.githubusercontent.com/civanmoreno/infraudit/main/install.sh | sh

# Run full audit
sudo infraudit audit
```

<details>
<summary><strong>Build from source</strong></summary>

Requires Go 1.24+:

```bash
git clone https://github.com/civanmoreno/infraudit.git
cd infraudit
make build
```

</details>

<details>
<summary><strong>Run with Docker</strong></summary>

```bash
docker build -t infraudit .
docker run --rm --privileged -v /:/host:ro infraudit audit
```

</details>

---

## 🔍 Usage

```bash
# Full audit (requires root for most checks)
sudo infraudit audit

# Audit specific categories (comma-separated)
sudo infraudit audit --category auth,network,crypto

# Run a single check
sudo infraudit audit --check AUTH-001

# Use a server profile
sudo infraudit audit --profile web-server

# Skip specific checks
sudo infraudit audit --skip HARD-007,SVC-012

# Export as JSON
sudo infraudit audit --format json --output report.json

# Generate visual HTML report
sudo infraudit audit --format html --output report.html

# Show only HIGH and CRITICAL findings
sudo infraudit audit --severity-min high

# Run checks in parallel (4 workers), quiet mode
sudo infraudit audit --parallel 4 --quiet

# Ignore permission errors in exit code
sudo infraudit audit --ignore-errors

# List checks (with filters)
infraudit list --category auth --severity high
infraudit list --format json

# Show available categories
infraudit categories
```

---

## 📊 Sample Output

```
  infraudit v1.1.0 — Security Audit Report
  ────────────────────────────────────────────────────

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
  █████████████████████████████████████████  5/8 checks
  ✓ 5 Passed    ! 2 Warnings    ✗ 1 Failures    0 Errors

  Hardening Index: 72/100 (C)
```

---

## 🛡️ Categories

| Category | Prefix | Checks | What it audits |
|:---------|:------:|:------:|:---------------|
| **auth** | `AUTH-` | 8 | Users, SSH, sudoers, passwords |
| **pam** | `PAM-` | 5 | Password quality, lockout, expiration |
| **network** | `NET-` | 11 | Firewall, ports, DNS, SNMP |
| **services** | `SVC-` | 13 | Daemons, NTP, MTA, desktop |
| **filesystem** | `FS-` | 12 | Permissions, SUID, partitions |
| **logging** | `LOG-` | 9 | Syslog, auditd, AIDE |
| **packages** | `PKG-` | 4 | Updates, repos, kernel |
| **hardening** | `HARD-` | 12 | Kernel params, ASLR, modules |
| **boot** | `BOOT-` | 8 | GRUB, Secure Boot, SELinux/AppArmor |
| **cron** | `CRON-` | 7 | Cron/at permissions, job review |
| **crypto** | `CRYPTO-` | 9 | TLS, certificates, ciphers |
| **secrets** | `SEC-` | 4 | Exposed credentials, history |
| **container** | `CTR-` | 11 | Docker/Podman security |
| **rlimit** | `RLIM-` | 7 | Resource limits, disk, inodes |
| **nfs** | `NFS-` | 4 | NFS exports, Samba, rpcbind |
| **malware** | `MAL-` | 4 | Rootkits, antimalware |
| **backup** | `BAK-` | 4 | Backups, encryption, off-site |

> 📋 See the **[Checks Reference](https://civanmoreno.github.io/infraudit/checks.html)** for detailed descriptions, security impact, and remediation for every check.

---

## 🎯 Severity Levels

| Level | Meaning | Response |
|:------|:--------|:---------|
| 🔴 **CRITICAL** | Exploitable vulnerability | Immediate action |
| 🟠 **HIGH** | Significant risk | Fix within days |
| 🟡 **MEDIUM** | Best practice not applied | Fix within weeks |
| 🔵 **LOW** | Recommended improvement | Backlog |
| ⚪ **INFO** | Informational | No action needed |

### Hardening Index

Every audit produces a **Hardening Index** (0–100) that summarizes your system's security posture in a single number. Each check is weighted by severity:

| Severity | Weight | PASS | WARN | FAIL |
|:---------|:-------|:-----|:-----|:-----|
| CRITICAL | 10 pts | +10 | +5 | 0 |
| HIGH | 5 pts | +5 | +2 | 0 |
| MEDIUM | 3 pts | +3 | +1 | 0 |
| LOW | 1 pt | +1 | +0 | 0 |
| INFO | 0 pts | — | — | — |

ERROR checks are excluded. The score maps to a letter grade: **A** (≥90), **B** (≥80), **C** (≥70), **D** (≥60), **F** (<60).

The score appears in console, JSON, YAML, and HTML output.

---

## 🖥️ Commands & Flags

### Commands

| Command | Description |
|:--------|:------------|
| `infraudit audit` | Run security checks and generate a report |
| `infraudit explain <ID>` | Explain a check in detail (CIS mapping, why it matters) |
| `infraudit list` | Show all available checks (filterable) |
| `infraudit categories` | Show available categories with check counts |
| `infraudit completion` | Generate shell autocompletion (bash, zsh, fish) |

### Audit Flags

| Flag | Default | Description |
|:-----|:--------|:------------|
| `--category` | *(all)* | Filter by categories (comma-separated: `auth,network`) |
| `--check` | *(none)* | Run a single check by ID (`AUTH-001`) |
| `--format` | `console` | Output format: `console`, `json`, `yaml`, `html` |
| `--output` | *(stdout)* | Write report to file |
| `--profile` | *(none)* | Server profile to apply |
| `--skip` | *(none)* | Comma-separated check IDs to skip |
| `--severity-min` | *(none)* | Show only results at or above this severity |
| `--status` | *(all)* | Show only results with these statuses (`fail,warn,error`) |
| `--parallel` | `0` | Run checks in parallel with N workers |
| `-q, --quiet` | `false` | Suppress progress output |
| `--ignore-errors` | `false` | Don't count errors toward exit code 2 |

---

## 📦 Server Profiles

Pre-built configurations for common server roles:

| Profile | Skipped categories | Allowed Ports |
|:--------|:-------------------|:--------------|
| `web-server` | container, nfs | 22, 80, 443 |
| `db-server` | container, nfs | 22, 3306, 5432, 6379, 27017 |
| `container-host` | nfs | 22, 80, 443, 2376 |
| `minimal` | container, nfs, malware, backup | 22 |

```bash
sudo infraudit audit --profile web-server
```

---

## ⚙️ Configuration

Create a config file for persistent settings:

```jsonc
// ~/.infraudit.json
{
  "skip": ["HARD-007", "SVC-012"],
  "skip_categories": ["container", "nfs"],
  "allowed_ports": [22, 80, 443],
  "allowed_root_processes": ["sshd", "nginx", "fail2ban"],
  "allowed_suid": ["/opt/myapp/bin/helper"],
  "command_timeout": 30
}
```

Config files are **merged** across all levels (system + user + directory). Values from higher-priority files extend lower ones, with deduplication:

| Priority | Path | Scope |
|:---------|:-----|:------|
| 1 (base) | `/etc/infraudit/config.json` | System-wide |
| 2 | `~/.infraudit.json` | User |
| 3 (top) | `./.infraudit.json` | Directory |

> ⚙️ Full details in the **[Configuration Guide](https://civanmoreno.github.io/infraudit/configuration.html)**

---

## 🛠️ Development

```bash
make build       # Build static binary
make test        # Run tests with race detector
make lint        # Run golangci-lint
make vet         # Run go vet
make cover       # Test coverage report
make release     # Cross-compile for amd64/arm64
make install-man # Install man page to /usr/share/man/man1
make docker      # Build Docker image
make clean       # Remove build artifacts
```

---

## 🔄 CI/CD Integration

Use exit codes to gate deployments:

| Code | Meaning | Action |
|:-----|:--------|:-------|
| `0` | All checks passed | Proceed |
| `1` | Warnings found | Review recommended |
| `2` | Failures or errors | Block deployment |

```bash
sudo infraudit audit --format json --output report.json
if [ $? -eq 2 ]; then
    echo "Security failures — blocking deployment"
    exit 1
fi
```

> 📊 See **[Output & Reports](https://civanmoreno.github.io/infraudit/output.html)** for JSON/YAML format details.

---

## 📏 Standards Coverage

| Standard | Coverage |
|:---------|:---------|
| CIS Benchmark Level 1 | ~90% of applicable controls |
| CIS Benchmark Level 2 | ~70% of applicable controls |
| DISA STIG | Key findings covered |
| Lynis categories | All major categories mapped |

---

## 📖 Documentation

Full documentation: **[civanmoreno.github.io/infraudit](https://civanmoreno.github.io/infraudit/)**

| Page | Description |
|:-----|:------------|
| [Getting Started](https://civanmoreno.github.io/infraudit/getting-started.html) | Installation, basic usage, CLI reference |
| [Checks Reference](https://civanmoreno.github.io/infraudit/checks.html) | All 132 checks with security impact and remediation |
| [Configuration](https://civanmoreno.github.io/infraudit/configuration.html) | Flags, config files, profiles |
| [Output & Reports](https://civanmoreno.github.io/infraudit/output.html) | Console, JSON, YAML formats and CI/CD integration |
| [Architecture](https://civanmoreno.github.io/infraudit/architecture.html) | Internal design and check interface |
| [Roadmap](https://civanmoreno.github.io/infraudit/roadmap.html) | Development phases and progress |

---

## License

[Business Source License 1.1](LICENSE)

You can **use** infraudit freely to audit your own servers. You **cannot** fork, redistribute, resell, or offer it as a service. After 4 years each version converts to Apache 2.0.
