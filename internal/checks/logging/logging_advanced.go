package logging

import (
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&journaldForward{})
	check.Register(&rsyslogRemote{})
	check.Register(&rsyslogNoReceive{})
	check.Register(&auditImmutable{})
	check.Register(&auditBacklog{})
	check.Register(&auditLoginUID{})
	check.Register(&logPermissions{})
	check.Register(&syslogInstalled{})
}

// LOG-028: journald forwards to rsyslog
type journaldForward struct{}

func (c *journaldForward) ID() string               { return "LOG-028" }
func (c *journaldForward) Name() string             { return "journald forwards to rsyslog" }
func (c *journaldForward) Category() string         { return "logging" }
func (c *journaldForward) Severity() check.Severity { return check.Low }
func (c *journaldForward) Description() string {
	return "Ensure journald is configured to forward logs to rsyslog"
}

func (c *journaldForward) Run() check.Result {
	val := journaldConfValue("ForwardToSyslog")
	if strings.EqualFold(val, "yes") {
		return check.Result{Status: check.Pass, Message: "journald ForwardToSyslog=yes"}
	}
	return check.Result{Status: check.Warn, Message: "journald ForwardToSyslog not enabled", Remediation: "Set ForwardToSyslog=yes in /etc/systemd/journald.conf"}
}

// LOG-029: rsyslog remote logging configured
type rsyslogRemote struct{}

func (c *rsyslogRemote) ID() string               { return "LOG-029" }
func (c *rsyslogRemote) Name() string             { return "rsyslog remote logging configured" }
func (c *rsyslogRemote) Category() string         { return "logging" }
func (c *rsyslogRemote) Severity() check.Severity { return check.Medium }
func (c *rsyslogRemote) Description() string {
	return "Ensure rsyslog is configured to send logs to a remote host"
}

func (c *rsyslogRemote) Run() check.Result {
	data, err := os.ReadFile("/etc/rsyslog.conf")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/rsyslog.conf"}
	}
	content := string(data)
	if strings.Contains(content, "@@") || strings.Contains(content, "action(type=\"omfwd\"") {
		return check.Result{Status: check.Pass, Message: "Remote logging is configured in rsyslog"}
	}
	return check.Result{Status: check.Warn, Message: "No remote logging configured in rsyslog", Remediation: "Add '*.* @@loghost.example.com:514' to /etc/rsyslog.conf"}
}

// LOG-030: rsyslog not configured to receive
type rsyslogNoReceive struct{}

func (c *rsyslogNoReceive) ID() string               { return "LOG-030" }
func (c *rsyslogNoReceive) Name() string             { return "rsyslog not accepting remote logs" }
func (c *rsyslogNoReceive) Category() string         { return "logging" }
func (c *rsyslogNoReceive) Severity() check.Severity { return check.Medium }
func (c *rsyslogNoReceive) Description() string {
	return "Ensure rsyslog is not configured to receive logs from remote clients (unless log server)"
}

func (c *rsyslogNoReceive) Run() check.Result {
	data, err := os.ReadFile("/etc/rsyslog.conf")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/rsyslog.conf"}
	}
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "imtcp") || strings.Contains(line, "imudp") {
			return check.Result{Status: check.Warn, Message: "rsyslog is configured to receive remote logs", Remediation: "Comment out imtcp/imudp modules in /etc/rsyslog.conf unless this is a log server"}
		}
	}
	return check.Result{Status: check.Pass, Message: "rsyslog is not accepting remote logs"}
}

// LOG-031: Audit configuration immutable
type auditImmutable struct{}

func (c *auditImmutable) ID() string               { return "LOG-031" }
func (c *auditImmutable) Name() string             { return "Audit configuration is immutable" }
func (c *auditImmutable) Category() string         { return "logging" }
func (c *auditImmutable) Severity() check.Severity { return check.Medium }
func (c *auditImmutable) Description() string {
	return "Ensure audit configuration is immutable (-e 2 flag)"
}

func (c *auditImmutable) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "auditctl", "-l")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read audit rules", Remediation: "Install auditd and run with sudo"}
	}
	if strings.Contains(string(out), "-e 2") {
		return check.Result{Status: check.Pass, Message: "Audit configuration is immutable (-e 2)"}
	}
	return check.Result{Status: check.Warn, Message: "Audit configuration is not set to immutable", Remediation: "Add '-e 2' as the last rule in /etc/audit/rules.d/99-finalize.rules"}
}

// LOG-032: Audit backlog limit
type auditBacklog struct{}

func (c *auditBacklog) ID() string               { return "LOG-032" }
func (c *auditBacklog) Name() string             { return "Audit backlog limit configured" }
func (c *auditBacklog) Category() string         { return "logging" }
func (c *auditBacklog) Severity() check.Severity { return check.Low }
func (c *auditBacklog) Description() string {
	return "Ensure audit backlog limit is sufficient"
}

func (c *auditBacklog) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "auditctl", "-s")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query audit status", Remediation: "Install auditd and run with sudo"}
	}
	if strings.Contains(string(out), "backlog_limit") {
		return check.Result{Status: check.Pass, Message: "Audit backlog limit is configured"}
	}
	return check.Result{Status: check.Warn, Message: "Audit backlog limit not configured", Remediation: "Add '-b 8192' to audit rules"}
}

// LOG-033: Audit tracks login UID
type auditLoginUID struct{}

func (c *auditLoginUID) ID() string               { return "LOG-033" }
func (c *auditLoginUID) Name() string             { return "Audit tracks login UID immutability" }
func (c *auditLoginUID) Category() string         { return "logging" }
func (c *auditLoginUID) Severity() check.Severity { return check.Medium }
func (c *auditLoginUID) Description() string {
	return "Ensure audit loginuid is immutable once set"
}

func (c *auditLoginUID) Run() check.Result {
	val := check.ReadSysctl("/proc/sys/kernel/audit_loginuid_immutable")
	if val == "1" {
		return check.Result{Status: check.Pass, Message: "audit loginuid is immutable"}
	}
	// Also check via audit rules
	out, _ := check.RunCmd(check.DefaultCmdTimeout, "auditctl", "-l")
	if strings.Contains(string(out), "--loginuid-immutable") {
		return check.Result{Status: check.Pass, Message: "loginuid immutability set via audit rules"}
	}
	return check.Result{Status: check.Warn, Message: "audit loginuid is not set to immutable", Remediation: "Add '--loginuid-immutable' to audit rules"}
}

// LOG-034: /var/log permissions
type logPermissions struct{}

func (c *logPermissions) ID() string               { return "LOG-034" }
func (c *logPermissions) Name() string             { return "/var/log directory permissions" }
func (c *logPermissions) Category() string         { return "logging" }
func (c *logPermissions) Severity() check.Severity { return check.Medium }
func (c *logPermissions) Description() string      { return "Ensure /var/log has restrictive permissions" }

func (c *logPermissions) Run() check.Result {
	info, err := os.Stat("/var/log")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot stat /var/log"}
	}
	perm := info.Mode().Perm()
	if perm <= 0o750 {
		return check.Result{Status: check.Pass, Message: "/var/log permissions are restrictive"}
	}
	return check.Result{Status: check.Warn, Message: "/var/log permissions are too open", Remediation: "chmod 750 /var/log"}
}

// LOG-035: Syslog-ng or rsyslog installed
type syslogInstalled struct{}

func (c *syslogInstalled) ID() string               { return "LOG-035" }
func (c *syslogInstalled) Name() string             { return "Syslog service installed and enabled" }
func (c *syslogInstalled) Category() string         { return "logging" }
func (c *syslogInstalled) Severity() check.Severity { return check.Medium }
func (c *syslogInstalled) Description() string {
	return "Ensure rsyslog or syslog-ng package is installed"
}

func (c *syslogInstalled) Run() check.Result {
	if check.PkgInstalled("rsyslog") || check.PkgInstalled("syslog-ng") {
		return check.Result{Status: check.Pass, Message: "Syslog package is installed"}
	}
	return check.Result{Status: check.Fail, Message: "No syslog package installed", Remediation: "apt install rsyslog / yum install rsyslog"}
}
