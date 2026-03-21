package auth

import (
	"bufio"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&sshRootLogin{})
}

type sshRootLogin struct{}

func (c *sshRootLogin) ID() string          { return "AUTH-001" }
func (c *sshRootLogin) Name() string        { return "SSH root login disabled" }
func (c *sshRootLogin) Category() string    { return "auth" }
func (c *sshRootLogin) Severity() check.Severity { return check.Critical }
func (c *sshRootLogin) Description() string { return "Verify that direct root login via SSH is disabled" }

func (c *sshRootLogin) Run() check.Result {
	val, err := sshdConfigValue("PermitRootLogin")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read sshd_config: " + err.Error(),
		}
	}

	if val == "" {
		return check.Result{
			Status:      check.Warn,
			Message:     "PermitRootLogin not explicitly set (default may allow root login)",
			Remediation: "Add 'PermitRootLogin no' to /etc/ssh/sshd_config",
		}
	}

	lower := strings.ToLower(val)
	if lower == "no" {
		return check.Result{
			Status:  check.Pass,
			Message: "PermitRootLogin is set to 'no'",
		}
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "PermitRootLogin is set to '" + val + "'",
		Remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd",
	}
}

// sshdConfigValue reads the effective value of a directive from sshd_config.
// It checks /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf.
func sshdConfigValue(directive string) (string, error) {
	paths := []string{"/etc/ssh/sshd_config"}

	// Also check drop-in configs
	entries, err := os.ReadDir("/etc/ssh/sshd_config.d")
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				paths = append(paths, "/etc/ssh/sshd_config.d/"+e.Name())
			}
		}
	}

	var lastValue string
	for _, path := range paths {
		v, err := parseSSHDirective(path, directive)
		if err != nil {
			continue
		}
		if v != "" {
			lastValue = v
		}
	}
	return lastValue, nil
}

func parseSSHDirective(path, directive string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	lower := strings.ToLower(directive)
	scanner := bufio.NewScanner(f)
	var value string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.ToLower(parts[0]) == lower {
			value = parts[1]
		}
	}
	return value, scanner.Err()
}
