package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

type filePermEntry struct {
	id      string
	name    string
	desc    string
	path    string
	maxPerm os.FileMode
}

func (c *filePermEntry) ID() string               { return c.id }
func (c *filePermEntry) Name() string             { return c.name }
func (c *filePermEntry) Category() string         { return "filesystem" }
func (c *filePermEntry) Severity() check.Severity { return check.Medium }
func (c *filePermEntry) Description() string      { return c.desc }

func (c *filePermEntry) Run() check.Result {
	return checkFilePerms(c.path, c.maxPerm)
}

func init() {
	for _, f := range filePermChecks {
		check.Register(f)
	}
	check.Register(&userDotFiles{})
	check.Register(&noForwardFiles{})
	check.Register(&noNetrcFiles{})
	check.Register(&noRhostsFiles{})
}

var filePermChecks = []*filePermEntry{
	{id: "FS-019", name: "/etc/cron.hourly permissions", desc: "Ensure permissions on /etc/cron.hourly", path: "/etc/cron.hourly", maxPerm: 0o700},
	{id: "FS-020", name: "/etc/cron.daily permissions", desc: "Ensure permissions on /etc/cron.daily", path: "/etc/cron.daily", maxPerm: 0o700},
	{id: "FS-021", name: "/etc/cron.weekly permissions", desc: "Ensure permissions on /etc/cron.weekly", path: "/etc/cron.weekly", maxPerm: 0o700},
	{id: "FS-022", name: "/etc/cron.monthly permissions", desc: "Ensure permissions on /etc/cron.monthly", path: "/etc/cron.monthly", maxPerm: 0o700},
	{id: "FS-023", name: "/etc/cron.d permissions", desc: "Ensure permissions on /etc/cron.d", path: "/etc/cron.d", maxPerm: 0o700},
	{id: "FS-024", name: "/etc/at.allow permissions", desc: "Ensure permissions on /etc/at.allow", path: "/etc/at.allow", maxPerm: 0o640},
	{id: "FS-025", name: "/etc/cron.allow permissions", desc: "Ensure permissions on /etc/cron.allow", path: "/etc/cron.allow", maxPerm: 0o640},
	{id: "FS-026", name: "/etc/ssh/sshd_config permissions", desc: "Ensure permissions on /etc/ssh/sshd_config", path: "/etc/ssh/sshd_config", maxPerm: 0o600},
	{id: "FS-027", name: "/etc/gshadow permissions", desc: "Ensure permissions on /etc/gshadow", path: "/etc/gshadow", maxPerm: 0o640},
	{id: "FS-028", name: "/etc/gshadow- permissions", desc: "Ensure permissions on /etc/gshadow- (backup)", path: "/etc/gshadow-", maxPerm: 0o640},
	{id: "FS-029", name: "/etc/passwd- permissions", desc: "Ensure permissions on /etc/passwd- (backup)", path: "/etc/passwd-", maxPerm: 0o644},
	{id: "FS-030", name: "/etc/shadow- permissions", desc: "Ensure permissions on /etc/shadow- (backup)", path: "/etc/shadow-", maxPerm: 0o640},
	{id: "FS-031", name: "/etc/group- permissions", desc: "Ensure permissions on /etc/group- (backup)", path: "/etc/group-", maxPerm: 0o644},
}

// FS-032: No .forward files
type noForwardFiles struct{}

func (c *noForwardFiles) ID() string               { return "FS-032" }
func (c *noForwardFiles) Name() string             { return "No user .forward files" }
func (c *noForwardFiles) Category() string         { return "filesystem" }
func (c *noForwardFiles) Severity() check.Severity { return check.Medium }
func (c *noForwardFiles) Description() string      { return "Ensure no users have .forward files" }

func (c *noForwardFiles) Run() check.Result {
	return checkUserDotFile(".forward")
}

// FS-033: No .netrc files
type noNetrcFiles struct{}

func (c *noNetrcFiles) ID() string               { return "FS-033" }
func (c *noNetrcFiles) Name() string             { return "No user .netrc files" }
func (c *noNetrcFiles) Category() string         { return "filesystem" }
func (c *noNetrcFiles) Severity() check.Severity { return check.Medium }
func (c *noNetrcFiles) Description() string      { return "Ensure no users have .netrc files" }

func (c *noNetrcFiles) Run() check.Result {
	return checkUserDotFile(".netrc")
}

// FS-034: No .rhosts files
type noRhostsFiles struct{}

func (c *noRhostsFiles) ID() string               { return "FS-034" }
func (c *noRhostsFiles) Name() string             { return "No user .rhosts files" }
func (c *noRhostsFiles) Category() string         { return "filesystem" }
func (c *noRhostsFiles) Severity() check.Severity { return check.High }
func (c *noRhostsFiles) Description() string      { return "Ensure no users have .rhosts files" }

func (c *noRhostsFiles) Run() check.Result {
	return checkUserDotFile(".rhosts")
}

// FS-035: User dot files not world-writable
type userDotFiles struct{}

func (c *userDotFiles) ID() string               { return "FS-035" }
func (c *userDotFiles) Name() string             { return "User dot files not world-writable" }
func (c *userDotFiles) Category() string         { return "filesystem" }
func (c *userDotFiles) Severity() check.Severity { return check.Medium }
func (c *userDotFiles) Description() string {
	return "Ensure users' dot files are not group or world writable"
}

func (c *userDotFiles) Run() check.Result {
	entries, err := check.ParsePasswd()
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot parse /etc/passwd"}
	}
	var issues []string
	for _, e := range entries {
		if e.UID < 1000 || e.Home == "" || e.Home == "/" {
			continue
		}
		dotFiles, _ := filepath.Glob(filepath.Join(e.Home, ".*"))
		for _, f := range dotFiles {
			info, err := os.Lstat(f)
			if err != nil || info.IsDir() {
				continue
			}
			perm := info.Mode().Perm()
			if perm&0o022 != 0 {
				issues = append(issues, fmt.Sprintf("%s (%04o)", f, perm))
			}
		}
	}
	if len(issues) > 0 {
		display := issues
		if len(display) > 5 {
			display = display[:5]
		}
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("%d world/group-writable dot files found", len(issues)),
			Remediation: "chmod go-w on affected dot files",
			Details:     map[string]string{"files": strings.Join(display, "\n")},
		}
	}
	return check.Result{Status: check.Pass, Message: "No world/group-writable user dot files"}
}

func checkUserDotFile(filename string) check.Result {
	entries, err := check.ParsePasswd()
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot parse /etc/passwd"}
	}
	var found []string
	for _, e := range entries {
		if e.UID < 1000 || e.Home == "" || e.Home == "/" {
			continue
		}
		path := filepath.Join(e.Home, filename)
		if _, err := os.Stat(path); err == nil {
			found = append(found, e.User)
		}
	}
	if len(found) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("%d users have %s files: %s", len(found), filename, strings.Join(found, ", ")),
			Remediation: fmt.Sprintf("Remove %s from user home directories", filename),
		}
	}
	return check.Result{Status: check.Pass, Message: fmt.Sprintf("No %s files found", filename)}
}
