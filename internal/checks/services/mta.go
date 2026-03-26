package services

import (
	"bufio"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&mtaLocalOnly{})
	check.Register(&mtaOpenRelay{})
	check.Register(&mtaRootAlias{})
}

// SVC-009: MTA local-only
type mtaLocalOnly struct{}

func (c *mtaLocalOnly) ID() string               { return "SVC-009" }
func (c *mtaLocalOnly) Name() string             { return "MTA configured as local-only" }
func (c *mtaLocalOnly) Category() string         { return "services" }
func (c *mtaLocalOnly) Severity() check.Severity { return check.High }
func (c *mtaLocalOnly) Description() string {
	return "Verify Postfix inet_interfaces is set to loopback-only"
}

func (c *mtaLocalOnly) Run() check.Result {
	val := postfixMainCfValue("inet_interfaces")
	if val == "" {
		if !check.ServiceActive("postfix") {
			return check.Result{Status: check.Pass, Message: "Postfix is not running"}
		}
		return check.Result{
			Status:      check.Warn,
			Message:     "Postfix running but inet_interfaces not explicitly set",
			Remediation: "Set 'inet_interfaces = loopback-only' in /etc/postfix/main.cf",
		}
	}

	lower := strings.ToLower(val)
	if lower == "loopback-only" || lower == "localhost" || lower == "127.0.0.1" {
		return check.Result{Status: check.Pass, Message: "MTA is configured as local-only (inet_interfaces=" + val + ")"}
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "MTA listens on external interfaces (inet_interfaces=" + val + ")",
		Remediation: "Set 'inet_interfaces = loopback-only' in /etc/postfix/main.cf",
	}
}

// SVC-010: Not an open relay
type mtaOpenRelay struct{}

func (c *mtaOpenRelay) ID() string               { return "SVC-010" }
func (c *mtaOpenRelay) Name() string             { return "MTA is not an open relay" }
func (c *mtaOpenRelay) Category() string         { return "services" }
func (c *mtaOpenRelay) Severity() check.Severity { return check.Critical }
func (c *mtaOpenRelay) Description() string {
	return "Verify Postfix does not relay mail for untrusted networks"
}

func (c *mtaOpenRelay) Run() check.Result {
	if !check.ServiceActive("postfix") {
		return check.Result{Status: check.Pass, Message: "Postfix is not running"}
	}

	networks := postfixMainCfValue("mynetworks")
	if networks == "" {
		return check.Result{Status: check.Pass, Message: "mynetworks uses default (local only)"}
	}

	// Flag if mynetworks contains broad ranges
	if strings.Contains(networks, "0.0.0.0/0") || strings.Contains(networks, "::/0") {
		return check.Result{
			Status:      check.Fail,
			Message:     "Postfix is an open relay (mynetworks=" + networks + ")",
			Remediation: "Restrict mynetworks to trusted hosts only in /etc/postfix/main.cf",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "Postfix mynetworks is restricted",
	}
}

// SVC-011: Root mail alias
type mtaRootAlias struct{}

func (c *mtaRootAlias) ID() string               { return "SVC-011" }
func (c *mtaRootAlias) Name() string             { return "Root mail forwarded to monitored account" }
func (c *mtaRootAlias) Category() string         { return "services" }
func (c *mtaRootAlias) Severity() check.Severity { return check.Low }
func (c *mtaRootAlias) Description() string      { return "Verify root mail is forwarded via /etc/aliases" }

func (c *mtaRootAlias) Run() check.Result {
	f, err := os.Open(check.P("/etc/aliases"))
	if err != nil {
		return check.Result{
			Status:      check.Warn,
			Message:     "Could not read /etc/aliases",
			Remediation: "Create /etc/aliases with 'root: admin@example.com' and run newaliases",
		}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "root:") || strings.HasPrefix(line, "root\t") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
				return check.Result{
					Status:  check.Pass,
					Message: "Root mail is forwarded to: " + strings.TrimSpace(parts[1]),
				}
			}
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "Root mail alias not configured",
		Remediation: "Add 'root: admin@example.com' to /etc/aliases and run newaliases",
	}
}

func postfixMainCfValue(key string) string {
	f, err := os.Open(check.P("/etc/postfix/main.cf"))
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
