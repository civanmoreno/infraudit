package network

import (
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&firewallActive{})
}

type firewallActive struct{}

func (c *firewallActive) ID() string               { return "NET-001" }
func (c *firewallActive) Name() string             { return "Firewall is active" }
func (c *firewallActive) Category() string         { return "network" }
func (c *firewallActive) Severity() check.Severity { return check.Critical }
func (c *firewallActive) Description() string {
	return "Verify a firewall (iptables, nftables, or ufw) is active"
}

func (c *firewallActive) Run() check.Result {
	// Check ufw
	if out, err := check.RunCmd(check.DefaultCmdTimeout, "ufw", "status"); err == nil {
		if strings.Contains(string(out), "Status: active") {
			return check.Result{
				Status:  check.Pass,
				Message: "ufw firewall is active",
			}
		}
	}

	// Check nftables
	if out, err := check.RunCmd(check.DefaultCmdTimeout, "nft", "list", "ruleset"); err == nil {
		output := strings.TrimSpace(string(out))
		if output != "" && strings.Contains(output, "table") {
			return check.Result{
				Status:  check.Pass,
				Message: "nftables firewall is active with rules loaded",
			}
		}
	}

	// Check iptables
	if out, err := check.RunCmd(check.DefaultCmdTimeout, "iptables", "-L", "-n"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		// More than just the default empty chains header
		if len(lines) > 8 {
			return check.Result{
				Status:  check.Pass,
				Message: "iptables firewall has rules configured",
			}
		}
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "No active firewall detected (checked ufw, nftables, iptables)",
		Remediation: "Enable a firewall: 'ufw enable' or configure nftables/iptables",
	}
}
