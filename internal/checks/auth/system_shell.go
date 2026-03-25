package auth

import (
	"fmt"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&systemShell{})
}

type systemShell struct{}

func (c *systemShell) ID() string               { return "AUTH-005" }
func (c *systemShell) Name() string             { return "System accounts have nologin shell" }
func (c *systemShell) Category() string         { return "auth" }
func (c *systemShell) Severity() check.Severity { return check.High }
func (c *systemShell) Description() string {
	return "Ensure system/service accounts use /sbin/nologin or /bin/false"
}

func (c *systemShell) Run() check.Result {
	entries, err := check.ParsePasswd()
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/passwd: " + err.Error(),
		}
	}

	safeShells := map[string]bool{
		"/sbin/nologin":     true,
		"/usr/sbin/nologin": true,
		"/bin/false":        true,
		"/usr/bin/false":    true,
	}

	allowed := map[string]bool{
		"root": true,
		"sync": true,
	}

	var bad []string
	for _, e := range entries {
		if allowed[e.User] || e.UID >= 1000 {
			continue
		}
		if e.Shell == "" || safeShells[e.Shell] {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s (shell: %s)", e.User, e.Shell))
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("System accounts with login shell: %s", strings.Join(bad, ", ")),
			Remediation: "Set shell to /sbin/nologin or /bin/false with 'usermod -s /sbin/nologin <user>'",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "All system accounts have non-login shells",
	}
}
