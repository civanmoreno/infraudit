package services

import (
	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	for _, s := range sshAdvancedSettings {
		check.Register(s)
	}
}

var sshAdvancedSettings = []*sshSetting{
	{id: "SVC-042", name: "SSH ClientAliveInterval configured", desc: "Ensure SSH idle timeout interval is configured", severity: check.Medium,
		directive: "ClientAliveInterval", expected: "300", compare: "le", remedy: "Set ClientAliveInterval 300 in /etc/ssh/sshd_config"},
	{id: "SVC-043", name: "SSH ClientAliveCountMax <= 3", desc: "Ensure SSH ClientAliveCountMax is set to 3 or less", severity: check.Medium,
		directive: "ClientAliveCountMax", expected: "3", compare: "le", remedy: "Set ClientAliveCountMax 3 in /etc/ssh/sshd_config"},
	{id: "SVC-044", name: "SSH LogLevel set to INFO or VERBOSE", desc: "Ensure SSH LogLevel is appropriately set", severity: check.Low,
		directive: "LogLevel", expected: "INFO", compare: "eq", remedy: "Set LogLevel INFO in /etc/ssh/sshd_config"},
	{id: "SVC-045", name: "SSH UsePAM enabled", desc: "Ensure SSH UsePAM is enabled", severity: check.Medium,
		directive: "UsePAM", expected: "yes", compare: "eq", remedy: "Set UsePAM yes in /etc/ssh/sshd_config"},
	{id: "SVC-046", name: "SSH DisableForwarding enabled", desc: "Ensure SSH forwarding is disabled", severity: check.Medium,
		directive: "DisableForwarding", expected: "yes", compare: "eq", remedy: "Set DisableForwarding yes in /etc/ssh/sshd_config"},
	{id: "SVC-047", name: "SSH GSSAPIAuthentication disabled", desc: "Ensure SSH GSSAPIAuthentication is disabled", severity: check.Low,
		directive: "GSSAPIAuthentication", expected: "no", compare: "eq", remedy: "Set GSSAPIAuthentication no in /etc/ssh/sshd_config"},
	{id: "SVC-048", name: "SSH KerberosAuthentication disabled", desc: "Ensure SSH KerberosAuthentication is disabled", severity: check.Low,
		directive: "KerberosAuthentication", expected: "no", compare: "eq", remedy: "Set KerberosAuthentication no in /etc/ssh/sshd_config"},
}
