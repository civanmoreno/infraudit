package services

import (
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&ntpSync{})
	check.Register(&ntpUser{})
	check.Register(&ntpNTS{})
	check.Register(&ntpSources{})
}

// SVC-003: NTP synchronized
type ntpSync struct{}

func (c *ntpSync) ID() string               { return "SVC-003" }
func (c *ntpSync) Name() string             { return "NTP/chrony running and synchronized" }
func (c *ntpSync) Category() string         { return "services" }
func (c *ntpSync) Severity() check.Severity { return check.Medium }
func (c *ntpSync) Description() string      { return "Verify time synchronization is active and working" }
func (c *ntpSync) RequiredInit() string     { return "systemd" }

func (c *ntpSync) Run() check.Result {
	// Check timedatectl
	out, err := check.RunCmd(check.DefaultCmdTimeout, "timedatectl", "show", "--property=NTPSynchronized")
	if err == nil {
		if strings.Contains(string(out), "NTPSynchronized=yes") {
			return check.Result{Status: check.Pass, Message: "System clock is NTP synchronized"}
		}
	}

	// Check if chrony or ntpd is running
	for _, svc := range []string{"chronyd", "chrony", "ntpd", "ntp", "systemd-timesyncd"} {
		sOut, sErr := check.RunCmd(check.DefaultCmdTimeout, "systemctl", "is-active", svc)
		if sErr == nil && strings.TrimSpace(string(sOut)) == "active" {
			return check.Result{
				Status:  check.Warn,
				Message: svc + " is running but clock may not be synchronized",
			}
		}
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "No NTP service detected",
		Remediation: "Install and enable chrony or systemd-timesyncd",
	}
}

// SVC-004: NTP not running as root
type ntpUser struct{}

func (c *ntpUser) ID() string               { return "SVC-004" }
func (c *ntpUser) Name() string             { return "NTP daemon not running as root" }
func (c *ntpUser) Category() string         { return "services" }
func (c *ntpUser) Severity() check.Severity { return check.Low }
func (c *ntpUser) Description() string      { return "Verify NTP daemon runs as a dedicated user" }

func (c *ntpUser) Run() check.Result {
	// chrony typically runs as _chrony or chrony
	out, err := check.RunCmd(check.DefaultCmdTimeout, "ps", "-eo", "user,comm")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Could not list processes"}
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		user, comm := fields[0], fields[1]
		if comm == "chronyd" || comm == "ntpd" {
			if user == "root" {
				return check.Result{
					Status:      check.Warn,
					Message:     comm + " is running as root",
					Remediation: "Configure " + comm + " to drop privileges to a dedicated user",
				}
			}
			return check.Result{
				Status:  check.Pass,
				Message: comm + " is running as user '" + user + "'",
			}
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No standalone NTP daemon running (may use systemd-timesyncd)",
	}
}

// SVC-005: NTS enabled
type ntpNTS struct{}

func (c *ntpNTS) ID() string               { return "SVC-005" }
func (c *ntpNTS) Name() string             { return "NTS (Network Time Security) enabled" }
func (c *ntpNTS) Category() string         { return "services" }
func (c *ntpNTS) Severity() check.Severity { return check.Low }
func (c *ntpNTS) Description() string {
	return "Check if NTS is enabled for authenticated time synchronization"
}

func (c *ntpNTS) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "chronyc", "authdata")
	if err == nil && strings.Contains(string(out), "NTS") {
		return check.Result{Status: check.Pass, Message: "NTS is configured in chrony"}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "NTS is not configured or chrony not available",
		Remediation: "Add 'nts' option to server lines in /etc/chrony/chrony.conf",
	}
}

// SVC-006: Trusted time sources
type ntpSources struct{}

func (c *ntpSources) ID() string               { return "SVC-006" }
func (c *ntpSources) Name() string             { return "Time sources are trusted" }
func (c *ntpSources) Category() string         { return "services" }
func (c *ntpSources) Severity() check.Severity { return check.Low }
func (c *ntpSources) Description() string {
	return "Verify NTP time sources are configured and reachable"
}

func (c *ntpSources) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "chronyc", "sources")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) > 2 {
			// Count reachable sources (lines with ^* or ^+)
			var reachable int
			for _, l := range lines {
				if strings.HasPrefix(l, "^*") || strings.HasPrefix(l, "^+") {
					reachable++
				}
			}
			if reachable > 0 {
				return check.Result{Status: check.Pass, Message: "Chrony has reachable time sources"}
			}
			return check.Result{
				Status:  check.Warn,
				Message: "Chrony sources configured but none are selected/reachable",
			}
		}
	}

	// Try ntpq
	out, err = check.RunCmd(check.DefaultCmdTimeout, "ntpq", "-p")
	if err == nil && len(strings.Split(string(out), "\n")) > 2 {
		return check.Result{Status: check.Pass, Message: "NTP has configured time sources"}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "Could not verify time sources",
		Remediation: "Configure reliable NTP sources in chrony or ntp config",
	}
}
