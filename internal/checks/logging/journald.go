package logging

import (
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&journaldCompress{})
	check.Register(&journaldPersistent{})
	check.Register(&rsyslogPerms{})
}

// LOG-025: journald compresses large logs
type journaldCompress struct{}

func (c *journaldCompress) ID() string               { return "LOG-025" }
func (c *journaldCompress) Name() string             { return "journald compresses large logs" }
func (c *journaldCompress) Category() string         { return "logging" }
func (c *journaldCompress) Severity() check.Severity { return check.Low }
func (c *journaldCompress) Description() string {
	return "Ensure journald is configured to compress large log files"
}

func (c *journaldCompress) Run() check.Result {
	val := journaldConfValue("Compress")
	if strings.EqualFold(val, "yes") || val == "" {
		return check.Result{Status: check.Pass, Message: "journald Compress is enabled (default yes)"}
	}
	return check.Result{
		Status:      check.Fail,
		Message:     "journald Compress is disabled",
		Remediation: "Set Compress=yes in /etc/systemd/journald.conf",
	}
}

// LOG-026: journald writes to persistent storage
type journaldPersistent struct{}

func (c *journaldPersistent) ID() string               { return "LOG-026" }
func (c *journaldPersistent) Name() string             { return "journald writes to persistent storage" }
func (c *journaldPersistent) Category() string         { return "logging" }
func (c *journaldPersistent) Severity() check.Severity { return check.Medium }
func (c *journaldPersistent) Description() string {
	return "Ensure journald is configured to write to persistent storage"
}

func (c *journaldPersistent) Run() check.Result {
	val := journaldConfValue("Storage")
	if strings.EqualFold(val, "persistent") {
		return check.Result{Status: check.Pass, Message: "journald Storage=persistent"}
	}
	return check.Result{
		Status:      check.Warn,
		Message:     "journald Storage is not set to persistent (current: " + val + ")",
		Remediation: "Set Storage=persistent in /etc/systemd/journald.conf",
	}
}

// LOG-027: rsyslog default file permissions
type rsyslogPerms struct{}

func (c *rsyslogPerms) ID() string               { return "LOG-027" }
func (c *rsyslogPerms) Name() string             { return "rsyslog default file permissions" }
func (c *rsyslogPerms) Category() string         { return "logging" }
func (c *rsyslogPerms) Severity() check.Severity { return check.Medium }
func (c *rsyslogPerms) Description() string {
	return "Ensure rsyslog default file permissions are configured (0640 or more restrictive)"
}

func (c *rsyslogPerms) Run() check.Result {
	data, err := os.ReadFile(check.P("/etc/rsyslog.conf"))
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/rsyslog.conf"}
	}
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "$FileCreateMode") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "$FileCreateMode"))
			if val <= "0640" {
				return check.Result{Status: check.Pass, Message: "rsyslog FileCreateMode = " + val}
			}
			return check.Result{
				Status:      check.Fail,
				Message:     "rsyslog FileCreateMode = " + val + " (too permissive)",
				Remediation: "Set $FileCreateMode 0640 in /etc/rsyslog.conf",
			}
		}
	}
	return check.Result{Status: check.Warn, Message: "FileCreateMode not set in rsyslog.conf", Remediation: "Add $FileCreateMode 0640 to /etc/rsyslog.conf"}
}

func journaldConfValue(key string) string {
	data, err := os.ReadFile(check.P("/etc/systemd/journald.conf"))
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
