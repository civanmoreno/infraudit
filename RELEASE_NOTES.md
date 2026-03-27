## Highlights

### GitHub Action
Official GitHub Action for CI/CD security audits with two execution modes:

```yaml
# Audit the GHA runner
- uses: civanmoreno/infraudit/action@v2
  with:
    min-score: 70

# Or audit a remote server via SSH
- uses: civanmoreno/infraudit/action@v2
  with:
    mode: ssh
    host: deploy@prod.example.com
    ssh-key: ${{ secrets.SSH_KEY }}
    min-score: 80
```

Features: auto-download binary, remote arch detection, SARIF upload for GitHub Code Scanning, min-score gate, job summary, fleet audits via matrix strategy.

### Homebrew Formula

```bash
brew tap civanmoreno/tap https://github.com/civanmoreno/infraudit.git
brew install infraudit
```

### Test Coverage: 36% to 47%
~110 new tests across 9 packages. All 17 check categories now have test coverage — zero packages at 0%.

## What's Changed

**New:**
- GitHub Action with local and SSH modes (`action/action.yml`)
- Homebrew formula (`Formula/infraudit.rb`)
- Auto-update script for formula SHA256 (`scripts/update-formula.sh`)
- ~110 new tests for boot, backup, malware, nfs, container, rlimit, packages, network, services

**Improved:**
- 15+ source files updated to use `check.P()` for test isolation
- Network tests: 9% to 53% (SNMP, DNS, IPv6, DNSSEC, DoT)
- Services tests: 23% to 32% (XDMCP, MTA, sudo, SSH)

**Full Changelog**: https://github.com/civanmoreno/infraudit/compare/v2.1.0...v2.2.0
