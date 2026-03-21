package network

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&bindAddress{})
}

type bindAddress struct{}

func (c *bindAddress) ID() string             { return "NET-004" }
func (c *bindAddress) Name() string           { return "Services not bound to 0.0.0.0 unnecessarily" }
func (c *bindAddress) Category() string       { return "network" }
func (c *bindAddress) Severity() check.Severity { return check.Medium }
func (c *bindAddress) Description() string    { return "Identify services listening on all interfaces (0.0.0.0) that could be restricted" }

func (c *bindAddress) Run() check.Result {
	// 0.0.0.0 in hex is 00000000
	wildcardListeners := findWildcardListeners("/proc/net/tcp")

	if len(wildcardListeners) == 0 {
		return check.Result{
			Status:  check.Pass,
			Message: "No services listening on 0.0.0.0 (all interfaces)",
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     fmt.Sprintf("%d services listening on all interfaces (0.0.0.0): ports %s", len(wildcardListeners), strings.Join(wildcardListeners, ", ")),
		Remediation: "Bind services to specific interfaces or localhost when possible",
	}
}

func findWildcardListeners(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ports []string
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" { // LISTEN only
			continue
		}
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}
		// 00000000 = 0.0.0.0
		if parts[0] == "00000000" {
			port := hexToPort(parts[1])
			if port > 0 {
				ports = append(ports, fmt.Sprintf("%d", port))
			}
		}
	}
	return ports
}
