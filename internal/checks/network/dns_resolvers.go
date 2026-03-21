package network

import (
	"bufio"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&dnsResolvers{})
}

type dnsResolvers struct{}

func (c *dnsResolvers) ID() string             { return "NET-005" }
func (c *dnsResolvers) Name() string           { return "DNS resolvers configured" }
func (c *dnsResolvers) Category() string       { return "network" }
func (c *dnsResolvers) Severity() check.Severity { return check.Low }
func (c *dnsResolvers) Description() string    { return "Verify DNS resolvers are configured in /etc/resolv.conf" }

func (c *dnsResolvers) Run() check.Result {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/resolv.conf: " + err.Error(),
		}
	}
	defer f.Close()

	var nameservers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			nameservers = append(nameservers, fields[1])
		}
	}

	if len(nameservers) == 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "No DNS resolvers configured in /etc/resolv.conf",
			Remediation: "Add nameserver entries to /etc/resolv.conf or configure systemd-resolved",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "DNS resolvers configured: " + strings.Join(nameservers, ", "),
	}
}
