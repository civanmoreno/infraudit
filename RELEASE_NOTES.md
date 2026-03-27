## Highlights

### OS Detection & Platform Awareness
infraudit now detects your OS family (Debian, RedHat, SUSE, Alpine, Arch), package manager, and init system at startup. Checks that don't apply to your platform are automatically **SKIPPED** — no more false positives from running RHEL-specific checks on Ubuntu or systemd checks in containers.

### YAML Plugin System
Define custom checks in `/etc/infraudit/checks.d/*.yaml` without recompiling:

```yaml
id: CUSTOM-001
name: App secure mode enabled
category: custom
severity: high
remediation: Set secure_mode=true in /etc/myapp/config
rule:
  type: file_contains
  path: /etc/myapp/config
  pattern: "secure_mode=true"
```

6 rule types: `file_exists`, `file_missing`, `file_contains`, `file_not_contains`, `file_perms`, `command`.

### Baseline & Regression Detection
Track security posture over time:

```bash
sudo infraudit baseline save        # Save current state
sudo infraudit baseline check       # Compare against baseline (exit 1 on regressions)
```

### Standards Documentation
New [Standards & Methodology](https://civanmoreno.github.io/infraudit/standards.html) page documenting how checks map to CIS Benchmarks, DISA STIG, NIST SP 800-53, PCI-DSS, SOC 2, HIPAA, and ISO 27001.

### Test Coverage: 10% → 36%
~270 new unit tests across 12 packages with FSRoot-based test isolation.

## What's Changed

**New Features:**
- OS detection (`internal/osinfo`) with 6 distro families
- SKIPPED status for platform-incompatible checks
- 26 checks annotated with OS/init requirements
- YAML plugin system with 6 rule types
- `infraudit baseline` command (save/check/show/clear)
- SVC-057: Redis authentication check
- Standards & Methodology docs page

**Bug Fixes:**
- SVC-052 no longer skipped on Debian containers without systemd (#25)
- `baseline check` now correctly compares checks by ID (#26)

**Governance:**
- SECURITY.md — vulnerability reporting policy
- CONTRIBUTING.md — contribution guide
- Issue templates (bug, feature, new check)
- PR template with checklist

**Full Changelog**: https://github.com/civanmoreno/infraudit/compare/v2.0.0...v2.1.0
