package logging

import (
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&auditLogSize{})
	check.Register(&auditLogFull{})
	check.Register(&auditLogRetain{})
	for _, r := range auditRuleChecks {
		check.Register(r)
	}
}

// LOG-010: Audit log storage size
type auditLogSize struct{}

func (c *auditLogSize) ID() string               { return "LOG-010" }
func (c *auditLogSize) Name() string             { return "Audit log storage size configured" }
func (c *auditLogSize) Category() string         { return "logging" }
func (c *auditLogSize) Severity() check.Severity { return check.Medium }
func (c *auditLogSize) Description() string {
	return "Ensure audit log storage size is configured in auditd.conf"
}

func (c *auditLogSize) Run() check.Result {
	val := auditdConfValue("max_log_file")
	if val == "" {
		return check.Result{Status: check.Warn, Message: "max_log_file not set in auditd.conf", Remediation: "Set max_log_file = 8 (MB) in /etc/audit/auditd.conf"}
	}
	return check.Result{Status: check.Pass, Message: fmt.Sprintf("max_log_file = %s MB", val)}
}

// LOG-011: System disabled when audit logs full
type auditLogFull struct{}

func (c *auditLogFull) ID() string               { return "LOG-011" }
func (c *auditLogFull) Name() string             { return "Action on audit log full" }
func (c *auditLogFull) Category() string         { return "logging" }
func (c *auditLogFull) Severity() check.Severity { return check.Medium }
func (c *auditLogFull) Description() string {
	return "Ensure system responds appropriately when audit logs are full"
}

func (c *auditLogFull) Run() check.Result {
	val := auditdConfValue("space_left_action")
	if val == "" || strings.EqualFold(val, "ignore") {
		return check.Result{Status: check.Fail, Message: "space_left_action not configured or set to ignore", Remediation: "Set space_left_action = email in /etc/audit/auditd.conf"}
	}
	return check.Result{Status: check.Pass, Message: fmt.Sprintf("space_left_action = %s", val)}
}

// LOG-012: Audit logs not automatically deleted
type auditLogRetain struct{}

func (c *auditLogRetain) ID() string               { return "LOG-012" }
func (c *auditLogRetain) Name() string             { return "Audit logs not auto-deleted" }
func (c *auditLogRetain) Category() string         { return "logging" }
func (c *auditLogRetain) Severity() check.Severity { return check.Medium }
func (c *auditLogRetain) Description() string {
	return "Ensure audit logs are not automatically deleted"
}

func (c *auditLogRetain) Run() check.Result {
	val := auditdConfValue("max_log_file_action")
	if strings.EqualFold(val, "rotate") || val == "" {
		return check.Result{Status: check.Warn, Message: "max_log_file_action allows rotation/deletion", Remediation: "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf"}
	}
	return check.Result{Status: check.Pass, Message: fmt.Sprintf("max_log_file_action = %s", val)}
}

// Audit rule checks (LOG-013 to LOG-024)
type auditRule struct {
	id      string
	name    string
	desc    string
	pattern string // pattern to search in auditctl -l output
	remedy  string
}

func (c *auditRule) ID() string               { return c.id }
func (c *auditRule) Name() string             { return c.name }
func (c *auditRule) Category() string         { return "logging" }
func (c *auditRule) Severity() check.Severity { return check.Medium }
func (c *auditRule) Description() string      { return c.desc }

func (c *auditRule) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "auditctl", "-l")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read audit rules (auditctl not available or no permission)", Remediation: "Install auditd and run with sudo: apt install auditd && sudo infraudit audit"}
	}
	rules := string(out)
	if strings.Contains(rules, c.pattern) {
		return check.Result{Status: check.Pass, Message: fmt.Sprintf("Audit rule for %s is configured", c.name)}
	}
	return check.Result{
		Status:      check.Fail,
		Message:     fmt.Sprintf("No audit rule for %s", c.name),
		Remediation: c.remedy,
	}
}

var auditRuleChecks = []*auditRule{
	{id: "LOG-013", name: "Audit: time-change events", desc: "Ensure events that modify date/time are collected", pattern: "adjtimex", remedy: "Add audit rule: -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"},
	{id: "LOG-014", name: "Audit: identity changes", desc: "Ensure events that modify user/group information are collected", pattern: "/etc/group", remedy: "Add audit rule: -w /etc/group -p wa -k identity"},
	{id: "LOG-015", name: "Audit: network environment changes", desc: "Ensure events that modify network environment are collected", pattern: "sethostname", remedy: "Add audit rule: -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"},
	{id: "LOG-016", name: "Audit: login/logout events", desc: "Ensure login and logout events are collected", pattern: "/var/log/lastlog", remedy: "Add audit rule: -w /var/log/lastlog -p wa -k logins"},
	{id: "LOG-017", name: "Audit: session initiation", desc: "Ensure session initiation information is collected", pattern: "/var/run/utmp", remedy: "Add audit rule: -w /var/run/utmp -p wa -k session"},
	{id: "LOG-018", name: "Audit: DAC permission changes", desc: "Ensure discretionary access control permission changes are collected", pattern: "chmod", remedy: "Add audit rule: -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod"},
	{id: "LOG-019", name: "Audit: unsuccessful file access", desc: "Ensure unsuccessful unauthorized file access attempts are collected", pattern: "EACCES", remedy: "Add audit rule: -a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access"},
	{id: "LOG-020", name: "Audit: privileged commands", desc: "Ensure use of privileged commands is collected", pattern: "execve", remedy: "Add audit rules for SUID/SGID binaries using find / -perm /6000"},
	{id: "LOG-021", name: "Audit: file system mounts", desc: "Ensure successful file system mounts are collected", pattern: "mount", remedy: "Add audit rule: -a always,exit -F arch=b64 -S mount -k mounts"},
	{id: "LOG-022", name: "Audit: file deletion events", desc: "Ensure file deletion events by users are collected", pattern: "unlink", remedy: "Add audit rule: -a always,exit -F arch=b64 -S unlink -S rename -k delete"},
	{id: "LOG-023", name: "Audit: sysadmin actions (sudoers)", desc: "Ensure changes to system administration scope are collected", pattern: "/etc/sudoers", remedy: "Add audit rule: -w /etc/sudoers -p wa -k scope"},
	{id: "LOG-024", name: "Audit: kernel module loading", desc: "Ensure kernel module loading and unloading is collected", pattern: "init_module", remedy: "Add audit rule: -a always,exit -F arch=b64 -S init_module -S delete_module -k modules"},
}

func auditdConfValue(key string) string {
	data, err := os.ReadFile("/etc/audit/auditd.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(parts[0]) == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
