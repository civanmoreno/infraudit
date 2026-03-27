package logging

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&syslogActive{})
	check.Register(&auditdRunning{})
	check.Register(&auditRules{})
	check.Register(&logRotation{})
	check.Register(&logPerms{})
	check.Register(&aideInstalled{})
	check.Register(&aideDB{})
	check.Register(&aideCron{})
	check.Register(&aidePaths{})
}

// LOG-001
type syslogActive struct{}

func (c *syslogActive) ID() string               { return "LOG-001" }
func (c *syslogActive) Name() string             { return "Syslog/journald active" }
func (c *syslogActive) Category() string         { return "logging" }
func (c *syslogActive) Severity() check.Severity { return check.Critical }
func (c *syslogActive) Description() string      { return "Verify logging service is running" }
func (c *syslogActive) RequiredInit() string     { return "systemd" }

func (c *syslogActive) Run() check.Result {
	for _, svc := range []string{"rsyslog", "syslog-ng", "systemd-journald"} {
		if check.ServiceActive(svc) {
			return check.Result{Status: check.Pass, Message: svc + " is active"}
		}
	}
	return check.Result{
		Status: check.Fail, Message: "No logging service detected",
		Remediation: "Install and enable rsyslog or ensure systemd-journald is running",
	}
}

// LOG-002
type auditdRunning struct{}

func (c *auditdRunning) ID() string               { return "LOG-002" }
func (c *auditdRunning) Name() string             { return "auditd installed and running" }
func (c *auditdRunning) Category() string         { return "logging" }
func (c *auditdRunning) Severity() check.Severity { return check.High }
func (c *auditdRunning) Description() string      { return "Verify auditd is installed and active" }
func (c *auditdRunning) RequiredInit() string     { return "systemd" }

func (c *auditdRunning) Run() check.Result {
	if check.ServiceActive("auditd") {
		return check.Result{Status: check.Pass, Message: "auditd is active"}
	}
	return check.Result{
		Status: check.Fail, Message: "auditd is not running",
		Remediation: "Install and enable: 'apt install auditd && systemctl enable --now auditd'",
	}
}

// LOG-003
type auditRules struct{}

func (c *auditRules) ID() string               { return "LOG-003" }
func (c *auditRules) Name() string             { return "Audit rules for sensitive files" }
func (c *auditRules) Category() string         { return "logging" }
func (c *auditRules) Severity() check.Severity { return check.High }
func (c *auditRules) Description() string {
	return "Verify audit rules watch /etc/passwd, /etc/shadow, sudoers"
}

func (c *auditRules) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "auditctl", "-l")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read audit rules (auditctl not available or not root)", Remediation: "Install auditd and run with sudo: apt install auditd && sudo infraudit audit"}
	}

	rules := string(out)
	watched := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers"}
	var missing []string
	for _, f := range watched {
		if !strings.Contains(rules, f) {
			missing = append(missing, f)
		}
	}

	if len(missing) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "No audit rules for: " + strings.Join(missing, ", "),
			Remediation: "Add watch rules: auditctl -w /etc/passwd -p wa -k identity",
		}
	}
	return check.Result{Status: check.Pass, Message: "Audit rules cover sensitive files"}
}

// LOG-004
type logRotation struct{}

func (c *logRotation) ID() string               { return "LOG-004" }
func (c *logRotation) Name() string             { return "Log rotation configured" }
func (c *logRotation) Category() string         { return "logging" }
func (c *logRotation) Severity() check.Severity { return check.Medium }
func (c *logRotation) Description() string      { return "Verify logrotate is installed and configured" }

func (c *logRotation) Run() check.Result {
	if _, err := os.Stat(check.P("/etc/logrotate.conf")); err == nil {
		return check.Result{Status: check.Pass, Message: "logrotate is configured"}
	}
	return check.Result{
		Status: check.Warn, Message: "logrotate configuration not found",
		Remediation: "Install logrotate and configure /etc/logrotate.conf",
	}
}

// LOG-005
type logPerms struct{}

func (c *logPerms) ID() string               { return "LOG-005" }
func (c *logPerms) Name() string             { return "Log files not world-readable" }
func (c *logPerms) Category() string         { return "logging" }
func (c *logPerms) Severity() check.Severity { return check.Medium }
func (c *logPerms) Description() string      { return "Verify log files in /var/log are not world-readable" }

func (c *logPerms) Run() check.Result {
	entries, err := os.ReadDir(check.P("/var/log"))
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /var/log"}
	}

	var bad []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0004 != 0 {
			bad = append(bad, e.Name())
		}
	}

	if len(bad) > 5 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("%d log files are world-readable", len(bad)),
			Remediation: "Fix permissions: chmod o-r /var/log/*",
		}
	}
	return check.Result{Status: check.Pass, Message: "Log file permissions are adequate"}
}

// LOG-006
type aideInstalled struct{}

func (c *aideInstalled) ID() string               { return "LOG-006" }
func (c *aideInstalled) Name() string             { return "AIDE or file integrity tool installed" }
func (c *aideInstalled) Category() string         { return "logging" }
func (c *aideInstalled) Severity() check.Severity { return check.High }
func (c *aideInstalled) Description() string {
	return "Verify a file integrity monitoring tool is installed"
}

func (c *aideInstalled) Run() check.Result {
	for _, tool := range []string{"aide", "tripwire", "samhain", "ossec-control"} {
		if _, err := exec.LookPath(tool); err == nil {
			return check.Result{Status: check.Pass, Message: tool + " is installed"}
		}
	}
	return check.Result{
		Status: check.Fail, Message: "No file integrity tool installed",
		Remediation: "Install AIDE: 'apt install aide' or 'dnf install aide'",
	}
}

// LOG-007
type aideDB struct{}

func (c *aideDB) ID() string               { return "LOG-007" }
func (c *aideDB) Name() string             { return "AIDE database initialized" }
func (c *aideDB) Category() string         { return "logging" }
func (c *aideDB) Severity() check.Severity { return check.Medium }
func (c *aideDB) Description() string      { return "Verify AIDE database has been initialized" }

func (c *aideDB) Run() check.Result {
	paths := []string{"/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db.new"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return check.Result{Status: check.Pass, Message: "AIDE database found: " + p}
		}
	}
	if _, err := exec.LookPath("aide"); err != nil {
		return check.Result{Status: check.Pass, Message: "AIDE is not installed (skipped)"}
	}
	return check.Result{
		Status: check.Warn, Message: "AIDE database not found",
		Remediation: "Initialize: 'aideinit' or 'aide --init'",
	}
}

// LOG-008
type aideCron struct{}

func (c *aideCron) ID() string               { return "LOG-008" }
func (c *aideCron) Name() string             { return "AIDE checks scheduled via cron" }
func (c *aideCron) Category() string         { return "logging" }
func (c *aideCron) Severity() check.Severity { return check.Medium }
func (c *aideCron) Description() string      { return "Verify AIDE integrity checks are scheduled" }

func (c *aideCron) Run() check.Result {
	if _, err := exec.LookPath("aide"); err != nil {
		return check.Result{Status: check.Pass, Message: "AIDE is not installed (skipped)"}
	}

	// Check cron directories
	cronDirs := []string{"/etc/cron.daily", "/etc/cron.weekly"}
	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), "aide") {
				return check.Result{Status: check.Pass, Message: "AIDE cron job found in " + dir}
			}
		}
	}

	// Check crontab
	out, _ := check.RunCmd(check.DefaultCmdTimeout, "grep", "-r", "aide", "/etc/crontab")
	if strings.TrimSpace(string(out)) != "" {
		return check.Result{Status: check.Pass, Message: "AIDE scheduled in /etc/crontab"}
	}

	return check.Result{
		Status: check.Warn, Message: "No AIDE cron job found",
		Remediation: "Add AIDE check to cron.daily or crontab",
	}
}

// LOG-009
type aidePaths struct{}

func (c *aidePaths) ID() string               { return "LOG-009" }
func (c *aidePaths) Name() string             { return "AIDE covers critical paths" }
func (c *aidePaths) Category() string         { return "logging" }
func (c *aidePaths) Severity() check.Severity { return check.Medium }
func (c *aidePaths) Description() string {
	return "Verify AIDE monitors /bin, /sbin, /lib, /etc, /boot"
}

func (c *aidePaths) Run() check.Result {
	confPath := "/etc/aide/aide.conf"
	if _, err := os.Stat(confPath); err != nil {
		confPath = "/etc/aide.conf"
		if _, err := os.Stat(confPath); err != nil {
			if _, err := exec.LookPath("aide"); err != nil {
				return check.Result{Status: check.Pass, Message: "AIDE is not installed (skipped)"}
			}
			return check.Result{Status: check.Warn, Message: "AIDE config not found"}
		}
	}

	data, err := os.ReadFile(confPath)
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read AIDE config"}
	}

	critical := []string{"/bin", "/sbin", "/lib", "/etc", "/boot"}
	content := string(data)

	var missing []string
	for _, p := range critical {
		if !strings.Contains(content, p) {
			missing = append(missing, p)
		}
	}

	if len(missing) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "AIDE may not cover: " + strings.Join(missing, ", "),
			Remediation: "Add missing paths to AIDE config",
		}
	}
	return check.Result{Status: check.Pass, Message: "AIDE covers critical paths"}
}
