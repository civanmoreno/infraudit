package filesystem

import (
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&homePerms{})
}

type homePerms struct{}

func (c *homePerms) ID() string               { return "FS-006" }
func (c *homePerms) Name() string             { return "Home directories not world-readable" }
func (c *homePerms) Category() string         { return "filesystem" }
func (c *homePerms) Severity() check.Severity { return check.Medium }
func (c *homePerms) Description() string {
	return "Verify user home directories are not world-readable or writable"
}

func (c *homePerms) Run() check.Result {
	entries, err := os.ReadDir(check.P("/home"))
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /home: " + err.Error()}
	}

	var bad []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		// Check if world-readable (o+r) or world-writable (o+w)
		if perm&0007 != 0 {
			bad = append(bad, fmt.Sprintf("%s (%04o)", e.Name(), perm))
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Home directories with world permissions: %s", strings.Join(bad, ", ")),
			Remediation: "Fix permissions: chmod 750 /home/*",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "All home directories have restrictive permissions",
	}
}
