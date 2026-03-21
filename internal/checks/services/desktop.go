package services

import (
	"os/exec"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&desktopEnv{})
	check.Register(&automount{})
}

// SVC-012: No desktop environment
type desktopEnv struct{}

func (c *desktopEnv) ID() string             { return "SVC-012" }
func (c *desktopEnv) Name() string           { return "No desktop environment installed" }
func (c *desktopEnv) Category() string       { return "services" }
func (c *desktopEnv) Severity() check.Severity { return check.Medium }
func (c *desktopEnv) Description() string    { return "Verify no GUI desktop environment is installed on the server" }

func (c *desktopEnv) Run() check.Result {
	// Check if gdm, lightdm, or sddm is active
	for _, dm := range []string{"gdm", "gdm3", "lightdm", "sddm"} {
		if check.ServiceActive(dm) {
			return check.Result{
				Status:      check.Warn,
				Message:     "Display manager '" + dm + "' is running on this server",
				Remediation: "Remove desktop environment: 'apt purge " + dm + "' or 'dnf remove @gnome-desktop'",
			}
		}
	}

	// Check default target
	out, err := exec.Command("systemctl", "get-default").CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) == "graphical.target" {
		return check.Result{
			Status:      check.Warn,
			Message:     "Default target is graphical.target",
			Remediation: "Set to multi-user: 'systemctl set-default multi-user.target'",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No desktop environment detected",
	}
}

// SVC-013: Automount disabled
type automount struct{}

func (c *automount) ID() string             { return "SVC-013" }
func (c *automount) Name() string           { return "Automount (autofs) disabled" }
func (c *automount) Category() string       { return "services" }
func (c *automount) Severity() check.Severity { return check.Medium }
func (c *automount) Description() string    { return "Verify autofs is not running" }

func (c *automount) Run() check.Result {
	if check.ServiceActive("autofs") {
		return check.Result{
			Status:      check.Warn,
			Message:     "autofs is running",
			Remediation: "Disable automount if not needed: 'systemctl disable --now autofs'",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "autofs is not running",
	}
}
