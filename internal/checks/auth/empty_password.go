package auth

import (
	"fmt"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&emptyPassword{})
}

type emptyPassword struct{}

func (c *emptyPassword) ID() string               { return "AUTH-004" }
func (c *emptyPassword) Name() string             { return "No users with empty password" }
func (c *emptyPassword) Category() string         { return "auth" }
func (c *emptyPassword) Severity() check.Severity { return check.Critical }
func (c *emptyPassword) Description() string {
	return "Ensure no user accounts have an empty password field"
}

func (c *emptyPassword) Run() check.Result {
	entries, err := check.ParseShadow()
	if err != nil {
		return check.Result{
			Status:      check.Error,
			Message:     "Could not read /etc/shadow: " + err.Error(),
			Remediation: "Run infraudit with sudo for full results",
		}
	}

	var bad []string
	for _, e := range entries {
		if e.Hash == "" {
			bad = append(bad, e.User)
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("Users with empty password: %s", strings.Join(bad, ", ")),
			Remediation: "Lock these accounts with 'passwd -l <user>' or set a strong password",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No users have empty passwords",
	}
}
