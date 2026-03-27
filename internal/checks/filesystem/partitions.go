package filesystem

import (
	"fmt"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&separatePartitions{})
	check.Register(&tmpCleanup{})
}

// FS-008: Separate partitions
type separatePartitions struct{}

func (c *separatePartitions) ID() string               { return "FS-008" }
func (c *separatePartitions) Name() string             { return "Separate partitions for key directories" }
func (c *separatePartitions) Category() string         { return "filesystem" }
func (c *separatePartitions) Severity() check.Severity { return check.Medium }
func (c *separatePartitions) Description() string {
	return "Verify /tmp, /var, /var/log, /var/log/audit, /home are separate partitions"
}

func (c *separatePartitions) Run() check.Result {
	mounts := check.ParseMounts()
	recommended := []string{"/tmp", "/var", "/var/log", "/var/log/audit", "/var/tmp", "/home"}

	var missing []string
	for _, path := range recommended {
		if findMount(mounts, path) == nil {
			missing = append(missing, path)
		}
	}

	if len(missing) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Not on separate partitions: %s", strings.Join(missing, ", ")),
			Remediation: "Consider creating separate partitions for isolation and quota management",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "All recommended directories are on separate partitions",
	}
}

// FS-012: Temp cleanup
type tmpCleanup struct{}

func (c *tmpCleanup) ID() string               { return "FS-012" }
func (c *tmpCleanup) Name() string             { return "Temporary file cleanup configured" }
func (c *tmpCleanup) Category() string         { return "filesystem" }
func (c *tmpCleanup) Severity() check.Severity { return check.Low }
func (c *tmpCleanup) Description() string {
	return "Verify systemd-tmpfiles or tmpreaper cleans temporary files"
}
func (c *tmpCleanup) RequiredInit() string { return "systemd" }

func (c *tmpCleanup) Run() check.Result {
	if check.ServiceActive("systemd-tmpfiles-clean.timer") {
		return check.Result{
			Status:  check.Pass,
			Message: "systemd-tmpfiles-clean.timer is active",
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "Temporary file cleanup timer is not active",
		Remediation: "Enable: 'systemctl enable --now systemd-tmpfiles-clean.timer'",
	}
}
