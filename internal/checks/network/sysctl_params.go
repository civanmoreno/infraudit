package network

import (
	"fmt"

	"github.com/civanmoreno/infraudit/internal/check"
)

type sysctlParam struct {
	id       string
	name     string
	desc     string
	severity check.Severity
	path     string
	expected string
	remedy   string
}

func (c *sysctlParam) ID() string               { return c.id }
func (c *sysctlParam) Name() string             { return c.name }
func (c *sysctlParam) Category() string         { return "network" }
func (c *sysctlParam) Severity() check.Severity { return c.severity }
func (c *sysctlParam) Description() string      { return c.desc }

func (c *sysctlParam) Run() check.Result {
	val := check.ReadSysctl(c.path)
	if val == "" {
		return check.Result{
			Status:  check.Error,
			Message: fmt.Sprintf("Cannot read %s", c.path),
		}
	}
	if val != c.expected {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("%s = %s (expected %s)", c.path, val, c.expected),
			Remediation: c.remedy,
		}
	}
	return check.Result{
		Status:  check.Pass,
		Message: fmt.Sprintf("%s = %s", c.path, val),
	}
}

func init() {
	for _, p := range sysctlParams {
		check.Register(p)
	}
}

var sysctlParams = []*sysctlParam{
	{
		id: "NET-012", name: "Packet redirect sending disabled (all)",
		desc: "Ensure send_redirects is disabled on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/all/send_redirects", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.all.send_redirects=0",
	},
	{
		id: "NET-013", name: "Packet redirect sending disabled (default)",
		desc: "Ensure send_redirects is disabled on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/default/send_redirects", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.default.send_redirects=0",
	},
	{
		id: "NET-014", name: "ICMP redirects not accepted (all)",
		desc: "Ensure ICMP redirects are not accepted on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/all/accept_redirects", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.all.accept_redirects=0",
	},
	{
		id: "NET-015", name: "ICMP redirects not accepted (default)",
		desc: "Ensure ICMP redirects are not accepted on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/default/accept_redirects", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.default.accept_redirects=0",
	},
	{
		id: "NET-016", name: "Secure ICMP redirects not accepted (all)",
		desc: "Ensure secure ICMP redirects are not accepted on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/all/secure_redirects", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.all.secure_redirects=0",
	},
	{
		id: "NET-017", name: "Secure ICMP redirects not accepted (default)",
		desc: "Ensure secure ICMP redirects are not accepted on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/default/secure_redirects", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.default.secure_redirects=0",
	},
	{
		id: "NET-018", name: "Suspicious packets logged (all)",
		desc: "Ensure suspicious packets are logged on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/all/log_martians", expected: "1",
		remedy: "sysctl -w net.ipv4.conf.all.log_martians=1",
	},
	{
		id: "NET-019", name: "Suspicious packets logged (default)",
		desc: "Ensure suspicious packets are logged on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/default/log_martians", expected: "1",
		remedy: "sysctl -w net.ipv4.conf.default.log_martians=1",
	},
	{
		id: "NET-020", name: "Broadcast ICMP requests ignored",
		desc: "Ensure broadcast ICMP requests are ignored", severity: check.Medium,
		path: "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", expected: "1",
		remedy: "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
	},
	{
		id: "NET-021", name: "Bogus ICMP responses ignored",
		desc: "Ensure bogus ICMP error responses are ignored", severity: check.Medium,
		path: "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses", expected: "1",
		remedy: "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1",
	},
	{
		id: "NET-022", name: "Reverse path filtering enabled (all)",
		desc: "Ensure reverse path filtering is enabled on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/all/rp_filter", expected: "1",
		remedy: "sysctl -w net.ipv4.conf.all.rp_filter=1",
	},
	{
		id: "NET-023", name: "Reverse path filtering enabled (default)",
		desc: "Ensure reverse path filtering is enabled on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/default/rp_filter", expected: "1",
		remedy: "sysctl -w net.ipv4.conf.default.rp_filter=1",
	},
	{
		id: "NET-024", name: "TCP SYN cookies enabled",
		desc: "Ensure TCP SYN cookies are enabled to prevent SYN flood attacks", severity: check.Medium,
		path: "/proc/sys/net/ipv4/tcp_syncookies", expected: "1",
		remedy: "sysctl -w net.ipv4.tcp_syncookies=1",
	},
	{
		id: "NET-025", name: "IPv6 router advertisements not accepted (all)",
		desc: "Ensure IPv6 router advertisements are not accepted on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv6/conf/all/accept_ra", expected: "0",
		remedy: "sysctl -w net.ipv6.conf.all.accept_ra=0",
	},
	{
		id: "NET-026", name: "IPv6 router advertisements not accepted (default)",
		desc: "Ensure IPv6 router advertisements are not accepted on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv6/conf/default/accept_ra", expected: "0",
		remedy: "sysctl -w net.ipv6.conf.default.accept_ra=0",
	},
	{
		id: "NET-027", name: "IPv6 redirects not accepted (all)",
		desc: "Ensure IPv6 redirects are not accepted on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv6/conf/all/accept_redirects", expected: "0",
		remedy: "sysctl -w net.ipv6.conf.all.accept_redirects=0",
	},
	{
		id: "NET-028", name: "IPv6 redirects not accepted (default)",
		desc: "Ensure IPv6 redirects are not accepted on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv6/conf/default/accept_redirects", expected: "0",
		remedy: "sysctl -w net.ipv6.conf.default.accept_redirects=0",
	},
	{
		id: "NET-029", name: "Source routed packets not accepted (all)",
		desc: "Ensure source routed packets are not accepted on all interfaces", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/all/accept_source_route", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.all.accept_source_route=0",
	},
	{
		id: "NET-030", name: "Source routed packets not accepted (default)",
		desc: "Ensure source routed packets are not accepted on default interface", severity: check.Medium,
		path: "/proc/sys/net/ipv4/conf/default/accept_source_route", expected: "0",
		remedy: "sysctl -w net.ipv4.conf.default.accept_source_route=0",
	},
	{
		id: "NET-031", name: "IPv6 source routing not accepted",
		desc: "Ensure IPv6 source routed packets are not accepted", severity: check.Medium,
		path: "/proc/sys/net/ipv6/conf/all/accept_source_route", expected: "0",
		remedy: "sysctl -w net.ipv6.conf.all.accept_source_route=0",
	},
}
