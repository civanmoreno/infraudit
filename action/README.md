# infraudit GitHub Action

Run infraudit security audits in your CI/CD pipeline — on the GitHub Actions runner or on remote servers via SSH.

## Execution Modes

| Mode | Usage | When to use |
|------|-------|-------------|
| `local` | Audits the GitHub Actions runner | Container testing, base image validation, CI environment auditing |
| `ssh` | Audits a remote server via SSH | Production servers, staging, pre-deploy checks |

## Quick Start

### Local Mode (on the runner)

```yaml
- name: Security Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    min-score: 70
```

### SSH Mode (remote server)

```yaml
- name: Security Audit (Production)
  uses: civanmoreno/infraudit/action@v2
  with:
    mode: ssh
    host: deploy@production.example.com
    ssh-key: ${{ secrets.SSH_PRIVATE_KEY }}
    min-score: 80
```

## Full Examples

### Basic audit with score gate

```yaml
name: Security Audit
on:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run infraudit
        uses: civanmoreno/infraudit/action@v2
        id: audit
        with:
          min-score: 70

      - name: Show results
        run: |
          echo "Score: ${{ steps.audit.outputs.score }}/100 (${{ steps.audit.outputs.grade }})"
          echo "Passed: ${{ steps.audit.outputs.passed }}/${{ steps.audit.outputs.total }}"
```

### Production server audit via SSH

```yaml
name: Production Security Check
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6am

jobs:
  audit-prod:
    runs-on: ubuntu-latest
    steps:
      - name: Audit production server
        uses: civanmoreno/infraudit/action@v2
        id: audit
        with:
          mode: ssh
          host: deploy@prod.example.com:22
          ssh-key: ${{ secrets.PROD_SSH_KEY }}
          profile: web-server
          min-score: 75
          format: sarif

      - name: Alert on low score
        if: failure()
        run: echo "::warning::Production score dropped below 75!"
```

### Multi-server audit

```yaml
name: Fleet Security Audit
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2am

jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        server:
          - { name: web-1, host: "deploy@web1.example.com", profile: web-server }
          - { name: db-1, host: "deploy@db1.example.com", profile: db-server }
          - { name: api-1, host: "deploy@api1.example.com", profile: web-server }
      fail-fast: false
    steps:
      - name: Audit ${{ matrix.server.name }}
        uses: civanmoreno/infraudit/action@v2
        id: audit
        with:
          mode: ssh
          host: ${{ matrix.server.host }}
          ssh-key: ${{ secrets.FLEET_SSH_KEY }}
          profile: ${{ matrix.server.profile }}
          min-score: 70
```

### With SARIF for GitHub Code Scanning

```yaml
- name: Security Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    format: sarif
    category: auth,network,crypto
```

Results appear in the **Security > Code Scanning** tab of the repository.

### With policy enforcement

```yaml
- name: Security Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    mode: ssh
    host: deploy@staging.example.com
    ssh-key: ${{ secrets.SSH_KEY }}
    policy: .infraudit-policy.json
```

### Specific categories only

```yaml
- name: SSH & Auth Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    category: auth,pam,crypto
    severity-min: high
    min-score: 80
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `mode` | `local` | `local` (GHA runner) or `ssh` (remote server) |
| `host` | — | SSH host: `user@hostname` or `user@hostname:port` |
| `ssh-key` | — | SSH private key for authentication |
| `ssh-password` | — | SSH password (if not using key) |
| `ssh-known-hosts` | — | known_hosts content (if empty, disables verification) |
| `category` | — | Filter by category (comma-separated) |
| `profile` | — | Server profile: `web-server`, `db-server`, `container-host`, `minimal` |
| `skip` | — | Check IDs to skip (comma-separated) |
| `severity-min` | — | Minimum severity: `low`, `medium`, `high`, `critical` |
| `format` | `sarif` | Format: `console`, `json`, `sarif` |
| `args` | — | Additional arguments for `infraudit audit` |
| `policy` | — | Path to policy file |
| `min-score` | — | Minimum score (0-100). Fails if below threshold |
| `version` | `latest` | infraudit version to use |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Hardening Index (0-100) |
| `grade` | Letter grade (A-F) |
| `total` | Total checks executed |
| `passed` | Checks that passed |
| `failures` | Checks that failed |
| `warnings` | Warnings |
| `report-path` | Path to the generated JSON report |

## Job Summary

The action automatically generates a summary in the workflow's **Summary** tab with:
- Score and grade
- Check count by status
- Table of CRITICAL and HIGH findings

## Security

- SSH keys are automatically cleaned up on completion (even on failure)
- If `ssh-known-hosts` is not provided, `StrictHostKeyChecking` is disabled (not recommended for production)
- For production, always provide `ssh-known-hosts` with the server's fingerprint
- Secrets should be stored as [GitHub Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
