package hardening

import (
	"fmt"
	"os"

	"github.com/civanmoreno/infraudit/internal/check"
)

type filePermCheck struct {
	id      string
	name    string
	desc    string
	path    string
	maxPerm os.FileMode
}

func (c *filePermCheck) ID() string               { return c.id }
func (c *filePermCheck) Name() string             { return c.name }
func (c *filePermCheck) Category() string         { return "hardening" }
func (c *filePermCheck) Severity() check.Severity { return check.Low }
func (c *filePermCheck) Description() string      { return c.desc }

func (c *filePermCheck) Run() check.Result {
	info, err := os.Stat(c.path)
	if os.IsNotExist(err) {
		return check.Result{Status: check.Pass, Message: c.path + " does not exist (OK)"}
	}
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot stat " + c.path}
	}
	perm := info.Mode().Perm()
	if perm <= c.maxPerm {
		return check.Result{Status: check.Pass, Message: fmt.Sprintf("%s permissions %04o", c.path, perm)}
	}
	return check.Result{
		Status:      check.Fail,
		Message:     fmt.Sprintf("%s permissions %04o (expected %04o or less)", c.path, perm, c.maxPerm),
		Remediation: fmt.Sprintf("chmod %04o %s && chown root:root %s", c.maxPerm, c.path, c.path),
	}
}

// HARD-013: GDM login banner
type gdmBanner struct{}

func (c *gdmBanner) ID() string               { return "HARD-013" }
func (c *gdmBanner) Name() string             { return "GDM login banner configured" }
func (c *gdmBanner) Category() string         { return "hardening" }
func (c *gdmBanner) Severity() check.Severity { return check.Low }
func (c *gdmBanner) Description() string {
	return "Ensure GDM login banner is configured if GDM is installed"
}

func (c *gdmBanner) Run() check.Result {
	// Check if GDM is installed
	if !check.PkgInstalled("gdm3", "gdm") {
		return check.Result{Status: check.Pass, Message: "GDM is not installed (skipped)"}
	}
	// Check dconf banner settings
	data, err := os.ReadFile("/etc/dconf/db/gdm.d/01-banner-message")
	if err != nil {
		return check.Result{Status: check.Warn, Message: "GDM banner not configured", Remediation: "Create /etc/dconf/db/gdm.d/01-banner-message with banner-message-enable=true"}
	}
	if len(data) > 0 {
		return check.Result{Status: check.Pass, Message: "GDM banner is configured"}
	}
	return check.Result{Status: check.Warn, Message: "GDM banner file is empty"}
}

func init() {
	check.Register(&gdmBanner{})
	check.Register(&filePermCheck{id: "HARD-014", name: "/etc/motd permissions", desc: "Ensure permissions on /etc/motd are configured", path: "/etc/motd", maxPerm: 0o644})
	check.Register(&filePermCheck{id: "HARD-015", name: "/etc/issue permissions", desc: "Ensure permissions on /etc/issue are configured", path: "/etc/issue", maxPerm: 0o644})
	check.Register(&filePermCheck{id: "HARD-016", name: "/etc/issue.net permissions", desc: "Ensure permissions on /etc/issue.net are configured", path: "/etc/issue.net", maxPerm: 0o644})
}
