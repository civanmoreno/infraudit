package network

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&snmpCommunity{})
}

type snmpCommunity struct{}

func (c *snmpCommunity) ID() string             { return "NET-010" }
func (c *snmpCommunity) Name() string           { return "Default SNMP community strings removed" }
func (c *snmpCommunity) Category() string       { return "network" }
func (c *snmpCommunity) Severity() check.Severity { return check.Critical }
func (c *snmpCommunity) Description() string    { return "Verify default SNMP community strings (public, private) are not in use" }

func (c *snmpCommunity) Run() check.Result {
	confPath := "/etc/snmp/snmpd.conf"
	f, err := os.Open(confPath)
	if err != nil {
		return check.Result{
			Status:  check.Pass,
			Message: "SNMP is not installed or configured",
		}
	}
	defer f.Close()

	defaults := []string{"public", "private"}
	var found []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "rocommunity") || strings.HasPrefix(line, "rwcommunity") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				for _, d := range defaults {
					if fields[1] == d {
						found = append(found, fmt.Sprintf("%s '%s'", fields[0], d))
					}
				}
			}
		}
	}

	if len(found) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "Default SNMP community strings in use: " + strings.Join(found, ", "),
			Remediation: "Remove default community strings 'public' and 'private' from /etc/snmp/snmpd.conf",
			Details:     map[string]string{"community_strings": strings.Join(found, "\n")},
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No default SNMP community strings found",
	}
}
