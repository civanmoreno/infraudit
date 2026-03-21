package filesystem

import (
	"fmt"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&stickyBit{})
}

type stickyBit struct{}

func (c *stickyBit) ID() string             { return "FS-003" }
func (c *stickyBit) Name() string           { return "Sticky bit set on /tmp and /var/tmp" }
func (c *stickyBit) Category() string       { return "filesystem" }
func (c *stickyBit) Severity() check.Severity { return check.High }
func (c *stickyBit) Description() string    { return "Verify sticky bit is set on world-writable directories" }

func (c *stickyBit) Run() check.Result {
	dirs := []string{"/tmp", "/var/tmp"}
	var missing []string

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSticky == 0 {
			missing = append(missing, dir)
		}
	}

	if len(missing) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("Sticky bit not set on: %s", strings.Join(missing, ", ")),
			Remediation: "Set sticky bit: chmod +t /tmp /var/tmp",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "Sticky bit is set on /tmp and /var/tmp",
	}
}
