package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

type sshSetting struct {
	id        string
	name      string
	desc      string
	severity  check.Severity
	directive string
	expected  string
	compare   string // "eq", "le", "ne", "nonempty"
	remedy    string
}

func (c *sshSetting) ID() string               { return c.id }
func (c *sshSetting) Name() string             { return c.name }
func (c *sshSetting) Category() string         { return "services" }
func (c *sshSetting) Severity() check.Severity { return c.severity }
func (c *sshSetting) Description() string      { return c.desc }

func (c *sshSetting) Run() check.Result {
	val := readSSHDirective(c.directive)
	if val == "" {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("SSH %s not explicitly set", c.directive),
			Remediation: c.remedy,
		}
	}

	passed := false
	switch c.compare {
	case "eq":
		passed = strings.EqualFold(val, c.expected)
	case "ne":
		passed = !strings.EqualFold(val, c.expected)
	case "le":
		n, err := strconv.Atoi(val)
		exp, _ := strconv.Atoi(c.expected)
		passed = err == nil && n <= exp
	case "nonempty":
		passed = val != ""
	}

	if passed {
		return check.Result{
			Status:  check.Pass,
			Message: fmt.Sprintf("SSH %s = %s", c.directive, val),
		}
	}
	return check.Result{
		Status:      check.Fail,
		Message:     fmt.Sprintf("SSH %s = %s (expected %s %s)", c.directive, val, c.compare, c.expected),
		Remediation: c.remedy,
	}
}

func init() {
	for _, s := range sshSettings {
		check.Register(s)
	}
	check.Register(&sudoPty{})
	check.Register(&sudoLog{})
}

var sshSettings = []*sshSetting{
	{id: "SVC-028", name: "SSH PermitEmptyPasswords disabled", desc: "Ensure SSH does not allow empty passwords", severity: check.High,
		directive: "PermitEmptyPasswords", expected: "no", compare: "eq", remedy: "Set PermitEmptyPasswords no in /etc/ssh/sshd_config"},
	{id: "SVC-029", name: "SSH MaxAuthTries <= 4", desc: "Ensure SSH MaxAuthTries is set to 4 or less", severity: check.Medium,
		directive: "MaxAuthTries", expected: "4", compare: "le", remedy: "Set MaxAuthTries 4 in /etc/ssh/sshd_config"},
	{id: "SVC-030", name: "SSH IgnoreRhosts enabled", desc: "Ensure SSH IgnoreRhosts is enabled", severity: check.Medium,
		directive: "IgnoreRhosts", expected: "yes", compare: "eq", remedy: "Set IgnoreRhosts yes in /etc/ssh/sshd_config"},
	{id: "SVC-031", name: "SSH HostbasedAuthentication disabled", desc: "Ensure SSH HostbasedAuthentication is disabled", severity: check.Medium,
		directive: "HostbasedAuthentication", expected: "no", compare: "eq", remedy: "Set HostbasedAuthentication no in /etc/ssh/sshd_config"},
	{id: "SVC-032", name: "SSH LoginGraceTime <= 60", desc: "Ensure SSH LoginGraceTime is 60 seconds or less", severity: check.Medium,
		directive: "LoginGraceTime", expected: "60", compare: "le", remedy: "Set LoginGraceTime 60 in /etc/ssh/sshd_config"},
	{id: "SVC-033", name: "SSH MaxStartups configured", desc: "Ensure SSH MaxStartups is configured to limit connections", severity: check.Medium,
		directive: "MaxStartups", expected: "", compare: "nonempty", remedy: "Set MaxStartups 10:30:60 in /etc/ssh/sshd_config"},
	{id: "SVC-034", name: "SSH MaxSessions <= 10", desc: "Ensure SSH MaxSessions is limited to 10 or less", severity: check.Medium,
		directive: "MaxSessions", expected: "10", compare: "le", remedy: "Set MaxSessions 10 in /etc/ssh/sshd_config"},
	{id: "SVC-035", name: "SSH Banner configured", desc: "Ensure SSH warning banner is configured", severity: check.Low,
		directive: "Banner", expected: "", compare: "nonempty", remedy: "Set Banner /etc/issue.net in /etc/ssh/sshd_config"},
	{id: "SVC-036", name: "SSH AllowTcpForwarding disabled", desc: "Ensure SSH AllowTcpForwarding is disabled", severity: check.Medium,
		directive: "AllowTcpForwarding", expected: "no", compare: "eq", remedy: "Set AllowTcpForwarding no in /etc/ssh/sshd_config"},
	{id: "SVC-037", name: "SSH X11Forwarding disabled", desc: "Ensure SSH X11Forwarding is disabled", severity: check.Medium,
		directive: "X11Forwarding", expected: "no", compare: "eq", remedy: "Set X11Forwarding no in /etc/ssh/sshd_config"},
	{id: "SVC-038", name: "SSH PermitUserEnvironment disabled", desc: "Ensure SSH PermitUserEnvironment is disabled", severity: check.Medium,
		directive: "PermitUserEnvironment", expected: "no", compare: "eq", remedy: "Set PermitUserEnvironment no in /etc/ssh/sshd_config"},
}

// readSSHDirective reads a directive value from sshd_config and drop-in files.
func readSSHDirective(directive string) string {
	paths := []string{"/etc/ssh/sshd_config"}
	dropins, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	paths = append(paths, dropins...)

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			// Handle both "Key Value" and "Key=Value"
			var key, val string
			if idx := strings.Index(line, "="); idx != -1 {
				key = strings.TrimSpace(line[:idx])
				val = strings.TrimSpace(line[idx+1:])
			} else {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					key = fields[0]
					val = fields[1]
				}
			}
			if strings.EqualFold(key, directive) {
				return val
			}
		}
	}
	return ""
}

// SVC-040: sudo uses pty
type sudoPty struct{}

func (c *sudoPty) ID() string               { return "SVC-040" }
func (c *sudoPty) Name() string             { return "Sudo commands use pty" }
func (c *sudoPty) Category() string         { return "services" }
func (c *sudoPty) Severity() check.Severity { return check.Medium }
func (c *sudoPty) Description() string {
	return "Ensure sudo commands use a pseudo-terminal (pty)"
}

func (c *sudoPty) Run() check.Result {
	if sudoersContains("use_pty") {
		return check.Result{Status: check.Pass, Message: "Defaults use_pty is configured"}
	}
	return check.Result{Status: check.Fail, Message: "Defaults use_pty not found in sudoers", Remediation: "Add 'Defaults use_pty' to /etc/sudoers via visudo"}
}

// SVC-041: sudo log file
type sudoLog struct{}

func (c *sudoLog) ID() string               { return "SVC-041" }
func (c *sudoLog) Name() string             { return "Sudo log file exists" }
func (c *sudoLog) Category() string         { return "services" }
func (c *sudoLog) Severity() check.Severity { return check.Medium }
func (c *sudoLog) Description() string {
	return "Ensure sudo log file is configured for audit trail"
}

func (c *sudoLog) Run() check.Result {
	if sudoersContains("logfile") {
		return check.Result{Status: check.Pass, Message: "Defaults logfile is configured in sudoers"}
	}
	return check.Result{Status: check.Warn, Message: "Defaults logfile not found in sudoers", Remediation: "Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers via visudo"}
}

func sudoersContains(keyword string) bool {
	paths := []string{"/etc/sudoers"}
	dropins, _ := filepath.Glob("/etc/sudoers.d/*")
	paths = append(paths, dropins...)

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), keyword) {
			return true
		}
	}
	return false
}
