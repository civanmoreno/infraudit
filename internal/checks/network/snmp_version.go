package network

import (
	"bufio"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&snmpVersion{})
}

type snmpVersion struct{}

func (c *snmpVersion) ID() string             { return "NET-009" }
func (c *snmpVersion) Name() string           { return "SNMP v1/v2c disabled" }
func (c *snmpVersion) Category() string       { return "network" }
func (c *snmpVersion) Severity() check.Severity { return check.High }
func (c *snmpVersion) Description() string    { return "Verify SNMP v1/v2c is disabled (only SNMPv3 if needed)" }

func (c *snmpVersion) Run() check.Result {
	// Check if snmpd is installed
	confPath := "/etc/snmp/snmpd.conf"
	f, err := os.Open(confPath)
	if err != nil {
		return check.Result{
			Status:  check.Pass,
			Message: "SNMP is not installed or configured",
		}
	}
	defer f.Close()

	var hasCommunity bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// rocommunity and rwcommunity are v1/v2c
		if strings.HasPrefix(line, "rocommunity") || strings.HasPrefix(line, "rwcommunity") {
			hasCommunity = true
			break
		}
	}

	if hasCommunity {
		return check.Result{
			Status:      check.Fail,
			Message:     "SNMP v1/v2c community strings found in snmpd.conf",
			Remediation: "Remove rocommunity/rwcommunity directives and use SNMPv3 with createUser/rouser",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No SNMP v1/v2c community strings configured",
	}
}
