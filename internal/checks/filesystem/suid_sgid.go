package filesystem

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&suidSgid{})
}

type suidSgid struct{}

func (c *suidSgid) ID() string             { return "FS-001" }
func (c *suidSgid) Name() string           { return "No unnecessary SUID/SGID files" }
func (c *suidSgid) Category() string       { return "filesystem" }
func (c *suidSgid) Severity() check.Severity { return check.High }
func (c *suidSgid) Description() string    { return "Find SUID/SGID files for review" }

// Known safe SUID binaries
var knownSUID = map[string]bool{
	"/usr/bin/sudo": true, "/usr/bin/su": true,
	"/usr/bin/passwd": true, "/usr/bin/chsh": true,
	"/usr/bin/chfn": true, "/usr/bin/newgrp": true,
	"/usr/bin/gpasswd": true, "/usr/bin/mount": true,
	"/usr/bin/umount": true, "/usr/bin/fusermount": true,
	"/usr/bin/fusermount3": true, "/usr/bin/pkexec": true,
	"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": true,
	"/usr/lib/openssh/ssh-keysign":                true,
	"/usr/libexec/openssh/ssh-keysign":            true,
	"/usr/bin/crontab":                            true,
	"/usr/bin/at":                                 true,
	"/usr/sbin/pam_timestamp_check":               true,
	"/usr/sbin/unix_chkpwd":                       true,
}

func (c *suidSgid) Run() check.Result {
	out, err := exec.Command("find", "/usr", "/bin", "/sbin",
		"-perm", "/6000", "-type", "f", "-print").CombinedOutput()
	if err != nil {
		return check.Result{Status: check.Error, Message: "Could not search for SUID/SGID files"}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var unknown []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !knownSUID[l] {
			unknown = append(unknown, l)
		}
	}

	if len(unknown) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Found %d SUID/SGID files not in known list (review recommended)", len(unknown)),
			Remediation: "Review and remove unnecessary SUID/SGID bits: chmod u-s,g-s <file>",
			Details:     map[string]string{"files": strings.Join(unknown, "\n")},
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "All SUID/SGID files are in the known safe list",
	}
}
