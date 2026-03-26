package remote

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Host represents a remote server to scan.
type Host struct {
	User     string
	Address  string
	Port     int
	Identity string
}

// String returns the host in user@address:port format.
func (h Host) String() string {
	s := h.Address
	if h.User != "" {
		s = h.User + "@" + s
	}
	if h.Port != 0 && h.Port != 22 {
		s += ":" + strconv.Itoa(h.Port)
	}
	return s
}

// ParseHost parses a host string in the format [user@]host[:port].
func ParseHost(s string) (Host, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Host{}, fmt.Errorf("empty host string")
	}

	h := Host{Port: 22}

	// Extract user
	if user, rest, ok := strings.Cut(s, "@"); ok {
		if user == "" {
			return Host{}, fmt.Errorf("empty user in host string")
		}
		h.User = user
		s = rest
	}

	// Extract port
	if idx := strings.LastIndex(s, ":"); idx != -1 {
		portStr := s[idx+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return Host{}, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
		if port < 1 || port > 65535 {
			return Host{}, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		h.Port = port
		s = s[:idx]
	}

	h.Address = s
	if h.Address == "" {
		return Host{}, fmt.Errorf("empty address in host string")
	}

	return h, nil
}

// ParseHostsFile reads a hosts file with one host per line.
// Lines starting with # and blank lines are ignored.
func ParseHostsFile(path string) ([]Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open hosts file: %w", err)
	}
	defer f.Close()

	var hosts []Host
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, err := ParseHost(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
		hosts = append(hosts, h)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read hosts file: %w", err)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts found in %s", path)
	}
	return hosts, nil
}
