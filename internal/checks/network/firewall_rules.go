package network

import (
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&fwDefaultDeny{})
	check.Register(&fwLoopback{})
	check.Register(&fwOutbound{})
	check.Register(&fwEstablished{})
	check.Register(&fwOpenPorts{})
	check.Register(&ip6DefaultDeny{})
	check.Register(&ip6Loopback{})
	check.Register(&ip6Established{})
}

// NET-032: Firewall default deny policy
type fwDefaultDeny struct{}

func (c *fwDefaultDeny) ID() string               { return "NET-032" }
func (c *fwDefaultDeny) Name() string             { return "Firewall default deny policy" }
func (c *fwDefaultDeny) Category() string         { return "network" }
func (c *fwDefaultDeny) Severity() check.Severity { return check.High }
func (c *fwDefaultDeny) Description() string {
	return "Ensure iptables/nftables default deny firewall policy is set"
}

func (c *fwDefaultDeny) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "iptables", "-L", "-n")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query iptables rules"}
	}
	rules := string(out)
	if strings.Contains(rules, "policy DROP") || strings.Contains(rules, "policy REJECT") {
		return check.Result{Status: check.Pass, Message: "iptables default policy is DROP/REJECT"}
	}
	// Check nftables
	out2, err := check.RunCmd(check.DefaultCmdTimeout, "nft", "list", "ruleset")
	if err == nil && (strings.Contains(string(out2), "policy drop") || strings.Contains(string(out2), "policy reject")) {
		return check.Result{Status: check.Pass, Message: "nftables default policy is drop/reject"}
	}
	return check.Result{Status: check.Fail, Message: "Firewall default policy is ACCEPT", Remediation: "Set default policy to DROP: iptables -P INPUT DROP && iptables -P FORWARD DROP"}
}

// NET-033: Firewall loopback traffic
type fwLoopback struct{}

func (c *fwLoopback) ID() string               { return "NET-033" }
func (c *fwLoopback) Name() string             { return "Firewall loopback traffic configured" }
func (c *fwLoopback) Category() string         { return "network" }
func (c *fwLoopback) Severity() check.Severity { return check.Medium }
func (c *fwLoopback) Description() string {
	return "Ensure loopback traffic is configured in firewall"
}

func (c *fwLoopback) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "iptables", "-L", "INPUT", "-n", "-v")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query iptables"}
	}
	if strings.Contains(string(out), "lo") && strings.Contains(string(out), "ACCEPT") {
		return check.Result{Status: check.Pass, Message: "Loopback traffic is allowed in firewall"}
	}
	return check.Result{Status: check.Warn, Message: "Loopback traffic rule not found", Remediation: "iptables -A INPUT -i lo -j ACCEPT && iptables -A OUTPUT -o lo -j ACCEPT"}
}

// NET-034: Firewall outbound established
type fwOutbound struct{}

func (c *fwOutbound) ID() string               { return "NET-034" }
func (c *fwOutbound) Name() string             { return "Firewall outbound connections configured" }
func (c *fwOutbound) Category() string         { return "network" }
func (c *fwOutbound) Severity() check.Severity { return check.Medium }
func (c *fwOutbound) Description() string      { return "Ensure outbound firewall rules are configured" }

func (c *fwOutbound) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "iptables", "-L", "OUTPUT", "-n", "-v")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query iptables"}
	}
	if len(string(out)) > 100 {
		return check.Result{Status: check.Pass, Message: "Outbound firewall rules are configured"}
	}
	return check.Result{Status: check.Warn, Message: "No outbound firewall rules configured"}
}

// NET-035: Firewall established connections
type fwEstablished struct{}

func (c *fwEstablished) ID() string               { return "NET-035" }
func (c *fwEstablished) Name() string             { return "Firewall allows established connections" }
func (c *fwEstablished) Category() string         { return "network" }
func (c *fwEstablished) Severity() check.Severity { return check.Medium }
func (c *fwEstablished) Description() string {
	return "Ensure established connections are allowed through firewall"
}

func (c *fwEstablished) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "iptables", "-L", "-n")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query iptables"}
	}
	if strings.Contains(string(out), "ESTABLISHED") || strings.Contains(string(out), "RELATED") {
		return check.Result{Status: check.Pass, Message: "Established/related connections are allowed"}
	}
	return check.Result{Status: check.Warn, Message: "No ESTABLISHED/RELATED rule found", Remediation: "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"}
}

// NET-036: Open ports have firewall rules
type fwOpenPorts struct{}

func (c *fwOpenPorts) ID() string               { return "NET-036" }
func (c *fwOpenPorts) Name() string             { return "All open ports have firewall rules" }
func (c *fwOpenPorts) Category() string         { return "network" }
func (c *fwOpenPorts) Severity() check.Severity { return check.Medium }
func (c *fwOpenPorts) Description() string {
	return "Ensure all open ports have corresponding firewall rules"
}

func (c *fwOpenPorts) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "iptables", "-L", "INPUT", "-n")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query iptables"}
	}
	rules := string(out)
	if strings.Contains(rules, "dpt:") || strings.Contains(rules, "ACCEPT") {
		return check.Result{Status: check.Pass, Message: "Firewall has port-specific rules"}
	}
	return check.Result{Status: check.Warn, Message: "No port-specific firewall rules found"}
}

// NET-037: IPv6 default deny
type ip6DefaultDeny struct{}

func (c *ip6DefaultDeny) ID() string               { return "NET-037" }
func (c *ip6DefaultDeny) Name() string             { return "IPv6 firewall default deny policy" }
func (c *ip6DefaultDeny) Category() string         { return "network" }
func (c *ip6DefaultDeny) Severity() check.Severity { return check.Medium }
func (c *ip6DefaultDeny) Description() string {
	return "Ensure IPv6 default deny firewall policy"
}

func (c *ip6DefaultDeny) Run() check.Result {
	// Check if IPv6 is disabled
	if check.ReadSysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6") == "1" {
		return check.Result{Status: check.Pass, Message: "IPv6 is disabled (firewall not needed)"}
	}
	out, err := check.RunCmd(check.DefaultCmdTimeout, "ip6tables", "-L", "-n")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query ip6tables"}
	}
	if strings.Contains(string(out), "policy DROP") || strings.Contains(string(out), "policy REJECT") {
		return check.Result{Status: check.Pass, Message: "ip6tables default policy is DROP/REJECT"}
	}
	return check.Result{Status: check.Fail, Message: "IPv6 firewall default policy is ACCEPT", Remediation: "ip6tables -P INPUT DROP && ip6tables -P FORWARD DROP"}
}

// NET-038: IPv6 loopback
type ip6Loopback struct{}

func (c *ip6Loopback) ID() string               { return "NET-038" }
func (c *ip6Loopback) Name() string             { return "IPv6 firewall loopback configured" }
func (c *ip6Loopback) Category() string         { return "network" }
func (c *ip6Loopback) Severity() check.Severity { return check.Medium }
func (c *ip6Loopback) Description() string      { return "Ensure IPv6 loopback traffic is configured" }

func (c *ip6Loopback) Run() check.Result {
	if check.ReadSysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6") == "1" {
		return check.Result{Status: check.Pass, Message: "IPv6 is disabled (skipped)"}
	}
	out, err := check.RunCmd(check.DefaultCmdTimeout, "ip6tables", "-L", "INPUT", "-n", "-v")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query ip6tables"}
	}
	if strings.Contains(string(out), "lo") {
		return check.Result{Status: check.Pass, Message: "IPv6 loopback traffic is configured"}
	}
	return check.Result{Status: check.Warn, Message: "IPv6 loopback traffic rule not found"}
}

// NET-039: IPv6 established
type ip6Established struct{}

func (c *ip6Established) ID() string               { return "NET-039" }
func (c *ip6Established) Name() string             { return "IPv6 firewall established connections" }
func (c *ip6Established) Category() string         { return "network" }
func (c *ip6Established) Severity() check.Severity { return check.Medium }
func (c *ip6Established) Description() string {
	return "Ensure IPv6 established connections are allowed"
}

func (c *ip6Established) Run() check.Result {
	if check.ReadSysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6") == "1" {
		return check.Result{Status: check.Pass, Message: "IPv6 is disabled (skipped)"}
	}
	out, err := check.RunCmd(check.DefaultCmdTimeout, "ip6tables", "-L", "-n")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot query ip6tables"}
	}
	if strings.Contains(string(out), "ESTABLISHED") {
		return check.Result{Status: check.Pass, Message: "IPv6 established connections allowed"}
	}
	return check.Result{Status: check.Warn, Message: "No IPv6 ESTABLISHED rule found"}
}
