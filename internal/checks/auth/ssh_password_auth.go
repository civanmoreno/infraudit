package auth

import (
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&sshPasswordAuth{})
}

type sshPasswordAuth struct{}

func (c *sshPasswordAuth) ID() string          { return "AUTH-002" }
func (c *sshPasswordAuth) Name() string        { return "SSH password authentication disabled" }
func (c *sshPasswordAuth) Category() string    { return "auth" }
func (c *sshPasswordAuth) Severity() check.Severity { return check.High }
func (c *sshPasswordAuth) Description() string { return "Verify that password authentication is disabled in SSH" }

func (c *sshPasswordAuth) Run() check.Result {
	val, err := sshdConfigValue("PasswordAuthentication")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read sshd_config: " + err.Error(),
		}
	}

	if val == "" {
		return check.Result{
			Status:      check.Warn,
			Message:     "PasswordAuthentication not explicitly set (default is 'yes')",
			Remediation: "Add 'PasswordAuthentication no' to /etc/ssh/sshd_config",
		}
	}

	if strings.ToLower(val) == "no" {
		return check.Result{
			Status:  check.Pass,
			Message: "PasswordAuthentication is set to 'no'",
		}
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "PasswordAuthentication is set to '" + val + "'",
		Remediation: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and restart sshd",
	}
}
