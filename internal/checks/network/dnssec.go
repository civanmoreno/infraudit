package network

import (
	"bufio"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&dnssec{})
}

type dnssec struct{}

func (c *dnssec) ID() string               { return "NET-006" }
func (c *dnssec) Name() string             { return "DNSSEC validation enabled" }
func (c *dnssec) Category() string         { return "network" }
func (c *dnssec) Severity() check.Severity { return check.Low }
func (c *dnssec) Description() string {
	return "Verify DNSSEC validation is enabled if running a local resolver"
}

func (c *dnssec) Run() check.Result {
	// Check systemd-resolved
	if val := resolvedConfValue("DNSSEC"); val != "" {
		lower := strings.ToLower(val)
		if lower == "yes" || lower == "true" {
			return check.Result{
				Status:  check.Pass,
				Message: "DNSSEC validation is enabled in systemd-resolved",
			}
		}
		if lower == "allow-downgrade" {
			return check.Result{
				Status:      check.Warn,
				Message:     "DNSSEC is set to allow-downgrade (partial protection)",
				Remediation: "Set DNSSEC=yes in /etc/systemd/resolved.conf for full validation",
			}
		}
		return check.Result{
			Status:      check.Warn,
			Message:     "DNSSEC validation is disabled in systemd-resolved (DNSSEC=" + val + ")",
			Remediation: "Set DNSSEC=yes in /etc/systemd/resolved.conf",
		}
	}

	// Check if unbound is configured
	if _, err := os.Stat("/etc/unbound/unbound.conf"); err == nil {
		return check.Result{
			Status:  check.Pass,
			Message: "Unbound resolver detected (DNSSEC enabled by default)",
		}
	}

	return check.Result{
		Status:  check.Warn,
		Message: "Could not determine DNSSEC validation status",
	}
}

func resolvedConfValue(key string) string {
	paths := []string{
		"/etc/systemd/resolved.conf",
	}
	// Also check drop-ins
	entries, err := os.ReadDir("/etc/systemd/resolved.conf.d")
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				paths = append(paths, "/etc/systemd/resolved.conf.d/"+e.Name())
			}
		}
	}

	for _, path := range paths {
		if val := iniValue(path, key); val != "" {
			return val
		}
	}
	return ""
}

func iniValue(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
