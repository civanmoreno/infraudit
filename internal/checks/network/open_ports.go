package network

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/config"
)

func init() {
	check.Register(&openPorts{})
}

type openPorts struct{}

func (c *openPorts) ID() string             { return "NET-002" }
func (c *openPorts) Name() string           { return "No unnecessary open ports" }
func (c *openPorts) Category() string       { return "network" }
func (c *openPorts) Severity() check.Severity { return check.High }
func (c *openPorts) Description() string    { return "List all listening TCP/UDP ports for review" }

func (c *openPorts) Run() check.Result {
	cfg := config.Get()
	allowed := make(map[int]bool)
	for _, p := range cfg.AllowedPorts {
		allowed[p] = true
	}

	var listening []string

	// Parse /proc/net/tcp and /proc/net/tcp6 for LISTEN state
	for _, proto := range []string{"tcp", "tcp6"} {
		ports := parseProcNet("/proc/net/" + proto)
		for _, p := range ports {
			port, _ := strconv.Atoi(p)
			if allowed[port] {
				continue
			}
			listening = append(listening, fmt.Sprintf("%s/%s", proto, p))
		}
	}

	if len(listening) == 0 {
		return check.Result{
			Status:  check.Pass,
			Message: "No unexpected listening TCP ports detected",
		}
	}

	return check.Result{
		Status:  check.Warn,
		Message: fmt.Sprintf("Found %d unexpected listening ports: %s", len(listening), strings.Join(listening, ", ")),
		Details: map[string]string{"ports": strings.Join(listening, "\n")},
	}
}

// parseProcNet reads /proc/net/tcp or tcp6 and returns ports in LISTEN state (0A).
func parseProcNet(path string) []string {
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
		if len(fields) < 4 {
			continue
		}
		// state is field 3, 0A = LISTEN
		if fields[3] != "0A" {
			continue
		}
		// local_address is field 1, format is hex IP:hex port
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}
		port := hexToPort(parts[1])
		if port > 0 {
			ports = append(ports, fmt.Sprintf("%d", port))
		}
	}
	return ports
}

func hexToPort(h string) int {
	var port int
	fmt.Sscanf(h, "%X", &port)
	return port
}
