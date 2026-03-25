package services

import (
	"fmt"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&criticalServices{})
}

type criticalServices struct{}

func (c *criticalServices) ID() string               { return "SVC-007" }
func (c *criticalServices) Name() string             { return "Critical services active" }
func (c *criticalServices) Category() string         { return "services" }
func (c *criticalServices) Severity() check.Severity { return check.High }
func (c *criticalServices) Description() string {
	return "Verify sshd and intrusion prevention (fail2ban/crowdsec) are running"
}

func (c *criticalServices) Run() check.Result {
	var missing []string

	// Check sshd
	if !check.ServiceActive("sshd") && !check.ServiceActive("ssh") {
		missing = append(missing, "sshd")
	}

	// Check intrusion prevention
	if !check.ServiceActive("fail2ban") && !check.ServiceActive("crowdsec") {
		missing = append(missing, "fail2ban/crowdsec")
	}

	if len(missing) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Missing critical services: %s", strings.Join(missing, ", ")),
			Remediation: "Install and enable fail2ban or crowdsec for intrusion prevention",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "Critical services (sshd, intrusion prevention) are active",
	}
}
