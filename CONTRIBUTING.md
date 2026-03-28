# Contributing to infraudit

Thank you for your interest in contributing. This document explains how to do it.

## Ways to Contribute

- **Report bugs** — Open an issue using the bug report template
- **Propose new checks** — Open an issue using the new check template
- **Create YAML plugins** — Share your custom checks
- **Improve documentation** — Corrections, translations, examples
- **Submit code** — Bug fixes, new checks, improvements

## Prerequisites

- Go 1.25+
- golangci-lint v2
- Familiarity with CIS Benchmarks or Linux security standards

## Environment Setup

```bash
git clone https://github.com/civanmoreno/infraudit.git
cd infraudit
make build    # Build
make test     # Run tests
make lint     # Run linter
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/my-change`
3. **Make your changes** following the code conventions
4. **Run tests and lint:**
   ```bash
   make test
   make lint
   ```
5. **Commit** with a descriptive message (see conventions below)
6. **Push** to your fork and open a Pull Request

### Commit Conventions

We use conventional commits:

```
feat: add check to validate Redis configuration
fix: fix false positive in AUTH-007 when shadow doesn't exist
docs: update plugin documentation
test: add tests for logging checks
refactor: consolidate sysctl parsers
```

Valid prefixes: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`

## Adding a New Check

### Built-in Check (Go)

1. Create a file in `internal/checks/<category>/`
2. Implement the `check.Check` interface:

```go
package auth

import "github.com/civanmoreno/infraudit/internal/check"

func init() {
    check.Register(&myCheck{})
}

type myCheck struct{}

func (c *myCheck) ID() string               { return "AUTH-XXX" }
func (c *myCheck) Name() string             { return "Short description" }
func (c *myCheck) Category() string         { return "auth" }
func (c *myCheck) Severity() check.Severity { return check.High }
func (c *myCheck) Description() string      { return "What this check validates" }

func (c *myCheck) Run() check.Result {
    // Check logic
    return check.Result{
        Status:      check.Pass,
        Message:     "All good",
    }
}
```

3. If the check depends on systemd, add:
```go
func (c *myCheck) RequiredInit() string { return "systemd" }
```

4. If the check is distro-specific:
```go
func (c *myCheck) SupportedOS() []string { return []string{"debian"} }
```

5. Use `check.P(path)` to resolve file paths (enables testing with FSRoot)
6. Add tests in `<category>/<category>_test.go`
7. Add the CIS mapping in `internal/compliance/cis.go` if applicable

### Plugin Check (YAML)

Create a file in `/etc/infraudit/checks.d/`:

```yaml
id: CUSTOM-001
name: My custom check
category: custom
severity: medium
description: What it validates
remediation: How to fix it
rule:
  type: file_contains
  path: /etc/my-app/config
  pattern: "secure=true"
```

See the [plugin documentation](https://civanmoreno.github.io/infraudit/configuration.html) for all rule types.

## Code Conventions

- **Formatting:** `gofmt` (enforced in CI)
- **Linting:** `golangci-lint` with the project config (`.golangci.yml`)
- **Tests:** Run with `-race` flag. Use `check.FSRoot` for tests of checks that read files.
- **Errors:** Return `check.Error` with a clear message when a check cannot execute. Do not use `panic`.
- **Test permissions:** Use `//nolint:gosec` when broad file permissions are needed in test files.
- **No new dependencies** unless strictly necessary. infraudit is deliberately minimal.

## Check IDs

| Category | Prefix | Current Range |
|----------|--------|---------------|
| auth | AUTH- | 001-022 |
| pam | PAM- | 001-013 |
| network | NET- | 001-035 |
| services | SVC- | 001-056 |
| filesystem | FS- | 001-035 |
| logging | LOG- | 001-035 |
| packages | PKG- | 001-004 |
| hardening | HARD- | 001-026 |
| boot | BOOT- | 001-008 |
| cron | CRON- | 001-007 |
| crypto | CRYPTO- | 001-009 |
| secrets | SEC- | 001-004 |
| container | CTR- | 001-011 |
| rlimit | RLIM- | 001-007 |
| nfs | NFS- | 001-004 |
| malware | MAL- | 001-004 |
| backup | BAK- | 001-004 |

When adding a new check, use the next available number in the corresponding category.

## Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for the vulnerability reporting process. **Do not open public issues for vulnerabilities.**

## License

By contributing, you agree that your contributions are licensed under the same terms as the project ([BSL 1.1](LICENSE)).
