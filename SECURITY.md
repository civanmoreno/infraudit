# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

infraudit is a security auditing tool that runs with elevated privileges and inspects sensitive system configurations. We take security very seriously.

**Do not open a public issue.** Instead:

1. Send an email to **security@infraudit.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact

2. You will receive a response within **48 hours**.

3. We will work with you to:
   - Confirm the vulnerability
   - Develop a fix
   - Coordinate disclosure

## Disclosure Process

We follow a responsible disclosure policy:

1. Report is received and confirmed (48h)
2. A fix is developed and tested (1-7 days depending on severity)
3. A release containing the fix is published
4. A GitHub security advisory is published
5. Credit is given to the reporter (if desired)

## Scope

The following types of findings are relevant:

- Arbitrary command execution through malicious inputs (YAML plugins, config files)
- Path traversal in file reading
- Command injection in checks that execute system commands
- Security validation bypasses
- Sensitive information exposure in reports or logs
- Vulnerabilities in dependencies

## Out of Scope

- Findings that require prior root access (infraudit already runs as root)
- False positives or false negatives in audit checks (report as a regular issue)
- Vulnerabilities in operating systems or tools that infraudit inspects
