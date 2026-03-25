package network

import (
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&ipv6Config{})
}

type ipv6Config struct{}

func (c *ipv6Config) ID() string               { return "NET-008" }
func (c *ipv6Config) Name() string             { return "IPv6 disabled or properly configured" }
func (c *ipv6Config) Category() string         { return "network" }
func (c *ipv6Config) Severity() check.Severity { return check.Medium }
func (c *ipv6Config) Description() string {
	return "Verify IPv6 is either disabled or properly configured"
}

func (c *ipv6Config) Run() check.Result {
	disableAll := check.ReadSysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6")

	if disableAll == "1" {
		return check.Result{
			Status:  check.Pass,
			Message: "IPv6 is disabled system-wide",
		}
	}

	// IPv6 is enabled — check if it's properly configured
	// Look for IPv6 addresses in /proc/net/if_inet6
	if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
		return check.Result{
			Status:  check.Pass,
			Message: "IPv6 is not available on this system",
		}
	}

	data, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return check.Result{
			Status:  check.Warn,
			Message: "IPv6 is enabled but could not read interface addresses",
		}
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) <= 1 {
		return check.Result{
			Status:  check.Pass,
			Message: "IPv6 is enabled but only loopback has addresses",
		}
	}

	// Check if accept_ra is disabled to prevent rogue RA attacks
	acceptRA := check.ReadSysctl("/proc/sys/net/ipv6/conf/all/accept_ra")
	if acceptRA != "0" {
		return check.Result{
			Status:      check.Warn,
			Message:     "IPv6 is enabled with Router Advertisement acceptance (accept_ra != 0)",
			Remediation: "Disable if not needed: sysctl -w net.ipv6.conf.all.disable_ipv6=1, or set net.ipv6.conf.all.accept_ra=0",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "IPv6 is enabled and Router Advertisements are rejected",
	}
}
