package backup

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&backupSchedule{})
	check.Register(&backupEncrypted{})
	check.Register(&backupPerms{})
	check.Register(&backupOffsite{})
}

// BAK-001
type backupSchedule struct{}

func (c *backupSchedule) ID() string             { return "BAK-001" }
func (c *backupSchedule) Name() string           { return "Backup schedule exists and ran recently" }
func (c *backupSchedule) Category() string       { return "backup" }
func (c *backupSchedule) Severity() check.Severity { return check.High }
func (c *backupSchedule) Description() string    { return "Verify backup jobs are scheduled and running" }

func (c *backupSchedule) Run() check.Result {
	// Check common backup tools
	backupTools := []string{"restic", "borg", "borgmatic", "duplicity", "rdiff-backup", "bacula-fd", "bareos-fd"}
	var installed []string
	for _, tool := range backupTools {
		if _, err := exec.LookPath(tool); err == nil {
			installed = append(installed, tool)
		}
	}

	// Check backup cron jobs
	cronDirs := []string{"/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.d"}
	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := strings.ToLower(e.Name())
			if strings.Contains(name, "backup") || strings.Contains(name, "borg") || strings.Contains(name, "restic") {
				return check.Result{Status: check.Pass, Message: "Backup cron job found: " + dir + "/" + e.Name()}
			}
		}
	}

	// Check systemd timers
	out, err := exec.Command("systemctl", "list-timers", "--no-pager").CombinedOutput()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "backup") || strings.Contains(lower, "borg") || strings.Contains(lower, "restic") {
				return check.Result{Status: check.Pass, Message: "Backup timer found"}
			}
		}
	}

	if len(installed) > 0 {
		return check.Result{
			Status:  check.Warn,
			Message: "Backup tools installed (" + strings.Join(installed, ", ") + ") but no schedule found",
			Remediation: "Configure a backup schedule via cron or systemd timer",
		}
	}

	return check.Result{
		Status: check.Warn, Message: "No backup tools or schedule detected",
		Remediation: "Install and configure a backup solution (restic, borg, etc.)",
	}
}

// BAK-002
type backupEncrypted struct{}

func (c *backupEncrypted) ID() string             { return "BAK-002" }
func (c *backupEncrypted) Name() string           { return "Backups are encrypted" }
func (c *backupEncrypted) Category() string       { return "backup" }
func (c *backupEncrypted) Severity() check.Severity { return check.Medium }
func (c *backupEncrypted) Description() string    { return "Check if backup solution uses encryption" }

func (c *backupEncrypted) Run() check.Result {
	// Check borg repo (encryption is configured at init)
	if _, err := exec.LookPath("borg"); err == nil {
		return check.Result{Status: check.Pass, Message: "Borg supports encryption (verify repo was initialized with encryption)"}
	}
	if _, err := exec.LookPath("restic"); err == nil {
		return check.Result{Status: check.Pass, Message: "Restic encrypts backups by default"}
	}
	return check.Result{
		Status:  check.Warn,
		Message: "Cannot verify backup encryption — ensure your backup solution encrypts data",
	}
}

// BAK-003
type backupPerms struct{}

func (c *backupPerms) ID() string             { return "BAK-003" }
func (c *backupPerms) Name() string           { return "Backup files not world-readable" }
func (c *backupPerms) Category() string       { return "backup" }
func (c *backupPerms) Severity() check.Severity { return check.High }
func (c *backupPerms) Description() string    { return "Verify backup directories have restrictive permissions" }

func (c *backupPerms) Run() check.Result {
	backupDirs := []string{"/var/backups", "/backup", "/srv/backup"}
	var bad []string

	for _, dir := range backupDirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&0007 != 0 {
			bad = append(bad, fmt.Sprintf("%s (%04o)", dir, perm))
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "Backup directories with world permissions: " + strings.Join(bad, ", "),
			Remediation: "Fix: chmod 700 <backup-dir>",
		}
	}

	// Check /var/backups freshness
	info, err := os.Stat("/var/backups")
	if err == nil {
		if time.Since(info.ModTime()) > 7*24*time.Hour {
			return check.Result{
				Status:  check.Warn,
				Message: "/var/backups not modified in over 7 days",
			}
		}
	}

	return check.Result{Status: check.Pass, Message: "Backup directory permissions are adequate"}
}

// BAK-004
type backupOffsite struct{}

func (c *backupOffsite) ID() string             { return "BAK-004" }
func (c *backupOffsite) Name() string           { return "Off-site/off-host backup exists" }
func (c *backupOffsite) Category() string       { return "backup" }
func (c *backupOffsite) Severity() check.Severity { return check.Medium }
func (c *backupOffsite) Description() string    { return "Verify backups are sent off-site or to a remote host" }

func (c *backupOffsite) Run() check.Result {
	// Check for remote backup config patterns
	if _, err := exec.LookPath("restic"); err == nil {
		// Restic supports s3, sftp, rest backends
		return check.Result{
			Status:  check.Warn,
			Message: "Restic installed — verify repository uses remote backend (s3, sftp, etc.)",
		}
	}
	if _, err := exec.LookPath("borg"); err == nil {
		return check.Result{
			Status:  check.Warn,
			Message: "Borg installed — verify repository is on a remote host",
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "Cannot verify off-site backup configuration",
		Remediation: "Configure backups to a remote location (S3, remote server, etc.)",
	}
}
