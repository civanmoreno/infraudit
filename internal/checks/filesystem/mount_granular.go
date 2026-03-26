package filesystem

import (
	"fmt"
	"os"

	"github.com/civanmoreno/infraudit/internal/check"
)

type separatePartition struct {
	id    string
	name  string
	desc  string
	mount string
	level check.Severity
}

func (c *separatePartition) ID() string               { return c.id }
func (c *separatePartition) Name() string             { return c.name }
func (c *separatePartition) Category() string         { return "filesystem" }
func (c *separatePartition) Severity() check.Severity { return c.level }
func (c *separatePartition) Description() string      { return c.desc }

func (c *separatePartition) Run() check.Result {
	mounts := check.ParseMounts()
	for _, m := range mounts {
		if m.Mount == c.mount {
			return check.Result{Status: check.Pass, Message: fmt.Sprintf("%s is on a separate partition (%s)", c.mount, m.Device)}
		}
	}
	return check.Result{
		Status:      check.Warn,
		Message:     fmt.Sprintf("%s is not on a separate partition", c.mount),
		Remediation: fmt.Sprintf("Create a separate partition for %s during system provisioning", c.mount),
	}
}

// FS-018: /etc/security/opasswd permissions
type opasswdPerms struct{}

func (c *opasswdPerms) ID() string               { return "FS-018" }
func (c *opasswdPerms) Name() string             { return "/etc/security/opasswd permissions" }
func (c *opasswdPerms) Category() string         { return "filesystem" }
func (c *opasswdPerms) Severity() check.Severity { return check.Medium }
func (c *opasswdPerms) Description() string {
	return "Ensure /etc/security/opasswd has permissions 0600 or more restrictive"
}

func (c *opasswdPerms) Run() check.Result {
	return checkFilePerms("/etc/security/opasswd", 0o600)
}

func init() {
	check.Register(&separatePartition{id: "FS-013", name: "/var is separate partition", desc: "Ensure /var is a separate partition", mount: "/var", level: check.Medium})
	check.Register(&separatePartition{id: "FS-014", name: "/var/log is separate partition", desc: "Ensure /var/log is a separate partition", mount: "/var/log", level: check.Medium})
	check.Register(&separatePartition{id: "FS-015", name: "/var/log/audit is separate partition", desc: "Ensure /var/log/audit is a separate partition", mount: "/var/log/audit", level: check.Medium})
	check.Register(&separatePartition{id: "FS-016", name: "/home is separate partition", desc: "Ensure /home is a separate partition", mount: "/home", level: check.Medium})
	check.Register(&homeNodev{})
	check.Register(&opasswdPerms{})
}

// FS-017: /home has nodev
type homeNodev struct{}

func (c *homeNodev) ID() string               { return "FS-017" }
func (c *homeNodev) Name() string             { return "/home has nodev option" }
func (c *homeNodev) Category() string         { return "filesystem" }
func (c *homeNodev) Severity() check.Severity { return check.Medium }
func (c *homeNodev) Description() string      { return "Ensure nodev option set on /home partition" }

func (c *homeNodev) Run() check.Result {
	mounts := check.ParseMounts()
	for _, m := range mounts {
		if m.Mount == "/home" {
			if check.HasMountOption(m.Options, "nodev") {
				return check.Result{Status: check.Pass, Message: "/home has nodev option"}
			}
			return check.Result{Status: check.Fail, Message: "/home is missing nodev option", Remediation: "Add nodev to /home mount options in /etc/fstab"}
		}
	}
	return check.Result{Status: check.Warn, Message: "/home is not a separate partition (nodev check skipped)", Remediation: "Create a separate /home partition with nodev option in /etc/fstab"}
}

func checkFilePerms(path string, maxPerm os.FileMode) check.Result {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return check.Result{Status: check.Pass, Message: path + " does not exist (OK)"}
	}
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot stat " + path}
	}
	perm := info.Mode().Perm()
	if perm <= maxPerm {
		return check.Result{Status: check.Pass, Message: fmt.Sprintf("%s permissions %04o (OK)", path, perm)}
	}
	return check.Result{
		Status:      check.Fail,
		Message:     fmt.Sprintf("%s permissions %04o (expected %04o or less)", path, perm, maxPerm),
		Remediation: fmt.Sprintf("chmod %04o %s", maxPerm, path),
	}
}
