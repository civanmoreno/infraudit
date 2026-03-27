package network

import (
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&snmpUnused{})
}

type snmpUnused struct{}

func (c *snmpUnused) ID() string               { return "NET-011" }
func (c *snmpUnused) Name() string             { return "SNMP removed if unused" }
func (c *snmpUnused) Category() string         { return "network" }
func (c *snmpUnused) Severity() check.Severity { return check.Low }
func (c *snmpUnused) Description() string      { return "Verify SNMP daemon is not installed if not needed" }

func (c *snmpUnused) Run() check.Result {
	// Check if snmpd config exists
	if _, err := os.Stat(check.P("/etc/snmp/snmpd.conf")); err != nil {
		return check.Result{
			Status:  check.Pass,
			Message: "SNMP is not installed",
		}
	}

	// Check if snmpd service is running
	out, err := check.RunCmd(check.DefaultCmdTimeout, "systemctl", "is-active", "snmpd")
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		return check.Result{
			Status:      check.Warn,
			Message:     "SNMP daemon (snmpd) is installed and running — verify it is needed",
			Remediation: "If SNMP is not required, remove it: 'apt purge snmpd' or 'dnf remove net-snmp'",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "SNMP is installed but not running",
	}
}
