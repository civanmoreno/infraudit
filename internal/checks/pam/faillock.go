package pam

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&faillock{})
}

type faillock struct{}

func (c *faillock) ID() string             { return "PAM-003" }
func (c *faillock) Name() string           { return "Account lockout after failed attempts" }
func (c *faillock) Category() string       { return "pam" }
func (c *faillock) Severity() check.Severity { return check.High }
func (c *faillock) Description() string {
	return "Verify pam_faillock is configured to lock accounts after failed login attempts"
}

func (c *faillock) Run() check.Result {
	// Check PAM configs for pam_faillock
	paths := []string{
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	}

	for _, path := range paths {
		if fileContainsActive(path, "pam_faillock.so") {
			return c.checkFaillockConf()
		}
	}

	// Also check if faillock.conf exists (newer approach)
	if _, err := os.Stat("/etc/security/faillock.conf"); err == nil {
		return c.checkFaillockConf()
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "pam_faillock is not configured",
		Remediation: "Configure pam_faillock in PAM auth stack or /etc/security/faillock.conf (deny=5, unlock_time=900)",
	}
}

func (c *faillock) checkFaillockConf() check.Result {
	conf := parseFaillockConf()

	var issues []string
	deny := conf["deny"]
	if deny == "" || atoi(deny) == 0 {
		issues = append(issues, "deny not set (recommended: 5)")
	} else if atoi(deny) > 10 {
		issues = append(issues, fmt.Sprintf("deny=%s is too permissive (recommended <= 5)", deny))
	}

	unlockTime := conf["unlock_time"]
	if unlockTime != "" && atoi(unlockTime) > 0 && atoi(unlockTime) < 600 {
		issues = append(issues, fmt.Sprintf("unlock_time=%s is too short (recommended >= 900)", unlockTime))
	}

	if len(issues) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "pam_faillock configured but: " + strings.Join(issues, ", "),
			Remediation: "Set deny=5, unlock_time=900 in /etc/security/faillock.conf",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: fmt.Sprintf("pam_faillock configured (deny=%s, unlock_time=%s)", deny, unlockTime),
	}
}

func parseFaillockConf() map[string]string {
	conf := make(map[string]string)

	// Try faillock.conf first
	f, err := os.Open("/etc/security/faillock.conf")
	if err != nil {
		return conf
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			conf[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		} else {
			// Some directives use space instead of =
			fields := strings.Fields(line)
			if len(fields) == 2 {
				conf[fields[0]] = fields[1]
			}
		}
	}
	return conf
}

func denyFromArgs(args string) int {
	for _, field := range strings.Fields(args) {
		if strings.HasPrefix(field, "deny=") {
			v, _ := strconv.Atoi(strings.TrimPrefix(field, "deny="))
			return v
		}
	}
	return 0
}
