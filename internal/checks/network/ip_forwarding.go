package network

import (
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&ipForwarding{})
}

type ipForwarding struct{}

func (c *ipForwarding) ID() string             { return "NET-003" }
func (c *ipForwarding) Name() string           { return "IP forwarding disabled" }
func (c *ipForwarding) Category() string       { return "network" }
func (c *ipForwarding) Severity() check.Severity { return check.Medium }
func (c *ipForwarding) Description() string    { return "Verify IP forwarding is disabled unless the system is a router/gateway" }

func (c *ipForwarding) Run() check.Result {
	v4 := check.ReadSysctl("/proc/sys/net/ipv4/ip_forward")
	v6 := check.ReadSysctl("/proc/sys/net/ipv6/conf/all/forwarding")

	var issues []string
	if v4 == "1" {
		issues = append(issues, "IPv4 forwarding is enabled")
	}
	if v6 == "1" {
		issues = append(issues, "IPv6 forwarding is enabled")
	}

	if len(issues) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     strings.Join(issues, "; "),
			Remediation: "If not a router, disable with: sysctl -w net.ipv4.ip_forward=0 and net.ipv6.conf.all.forwarding=0",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "IP forwarding is disabled (IPv4 and IPv6)",
	}
}

