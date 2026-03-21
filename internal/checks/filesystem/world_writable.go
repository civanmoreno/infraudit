package filesystem

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&worldWritable{})
}

type worldWritable struct{}

func (c *worldWritable) ID() string             { return "FS-002" }
func (c *worldWritable) Name() string           { return "No world-writable files outside /tmp" }
func (c *worldWritable) Category() string       { return "filesystem" }
func (c *worldWritable) Severity() check.Severity { return check.High }
func (c *worldWritable) Description() string    { return "Find world-writable files outside temporary directories" }

func (c *worldWritable) Run() check.Result {
	out, err := exec.Command("find", "/", "-xdev",
		"-path", "/tmp", "-prune", "-o",
		"-path", "/var/tmp", "-prune", "-o",
		"-path", "/dev", "-prune", "-o",
		"-path", "/proc", "-prune", "-o",
		"-path", "/sys", "-prune", "-o",
		"-path", "/run", "-prune", "-o",
		"-type", "f", "-perm", "-0002", "-print").CombinedOutput()
	if err != nil {
		// find may return non-zero due to permission denied on some dirs
		// but still output results
	}

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
		if len(display) > 20 {
			display = display[:20]
		}
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("Found %d world-writable files outside /tmp", len(files)),
			Remediation: "Remove world-writable permission: chmod o-w <file>",
			Details:     map[string]string{"files": strings.Join(display, "\n")},
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No world-writable files found outside temporary directories",
	}
}
