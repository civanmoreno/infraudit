package network

import (
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&dnsTLS{})
}

type dnsTLS struct{}

func (c *dnsTLS) ID() string               { return "NET-007" }
func (c *dnsTLS) Name() string             { return "DNS over TLS/HTTPS configured" }
func (c *dnsTLS) Category() string         { return "network" }
func (c *dnsTLS) Severity() check.Severity { return check.Low }
func (c *dnsTLS) Description() string      { return "Verify DNS queries are encrypted via DoT or DoH" }

func (c *dnsTLS) Run() check.Result {
	// Check systemd-resolved DNSOverTLS setting
	val := resolvedConfValue("DNSOverTLS")
	if val != "" {
		lower := strings.ToLower(val)
		if lower == "yes" || lower == "true" {
			return check.Result{
				Status:  check.Pass,
				Message: "DNS over TLS is enabled in systemd-resolved",
			}
		}
		if lower == "opportunistic" {
			return check.Result{
				Status:  check.Pass,
				Message: "DNS over TLS is set to opportunistic in systemd-resolved",
			}
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "DNS over TLS/HTTPS is not configured",
		Remediation: "Set DNSOverTLS=yes in /etc/systemd/resolved.conf or configure a DoT/DoH-capable resolver",
	}
}
