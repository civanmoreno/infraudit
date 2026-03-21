package filesystem

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&orphanedFiles{})
}

type orphanedFiles struct{}

func (c *orphanedFiles) ID() string             { return "FS-007" }
func (c *orphanedFiles) Name() string           { return "No orphaned files" }
func (c *orphanedFiles) Category() string       { return "filesystem" }
func (c *orphanedFiles) Severity() check.Severity { return check.Low }
func (c *orphanedFiles) Description() string    { return "Find files without a valid owner or group" }

func (c *orphanedFiles) Run() check.Result {
	out, _ := exec.Command("find", "/usr", "/etc", "/var",
		"-xdev", "-nouser", "-o", "-nogroup").CombinedOutput()

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var files []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			files = append(files, l)
		}
	}

	if len(files) > 0 {
		display := files
		if len(display) > 10 {
			display = display[:10]
		}
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Found %d orphaned files (no valid owner/group)", len(files)),
			Remediation: "Assign proper ownership: chown root:root <file>",
			Details:     map[string]string{"files": strings.Join(display, "\n")},
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No orphaned files found",
	}
}
