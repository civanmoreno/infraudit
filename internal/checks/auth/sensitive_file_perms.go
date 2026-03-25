package auth

import (
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&sensitiveFilePerms{})
}

type sensitiveFilePerms struct{}

func (c *sensitiveFilePerms) ID() string               { return "AUTH-007" }
func (c *sensitiveFilePerms) Name() string             { return "Sensitive auth files have correct permissions" }
func (c *sensitiveFilePerms) Category() string         { return "auth" }
func (c *sensitiveFilePerms) Severity() check.Severity { return check.High }
func (c *sensitiveFilePerms) Description() string {
	return "Verify /etc/passwd, /etc/shadow, and /etc/group have secure permissions"
}

type filePermCheck struct {
	path    string
	maxPerm os.FileMode
	owner   uint32 // expected UID (0 = root)
}

func (c *sensitiveFilePerms) Run() check.Result {
	checks := []filePermCheck{
		{"/etc/passwd", 0644, 0},
		{"/etc/shadow", 0640, 0},
		{"/etc/group", 0644, 0},
	}

	var bad []string
	for _, fc := range checks {
		info, err := os.Stat(fc.path)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %s", fc.path, err.Error()))
			continue
		}

		perm := info.Mode().Perm()
		if perm > fc.maxPerm {
			bad = append(bad, fmt.Sprintf("%s has %04o (expected %04o or stricter)", fc.path, perm, fc.maxPerm))
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("Insecure permissions: %s", strings.Join(bad, "; ")),
			Remediation: "Fix with: chmod 644 /etc/passwd /etc/group && chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "Permissions on /etc/passwd, /etc/shadow, /etc/group are correct",
	}
}
