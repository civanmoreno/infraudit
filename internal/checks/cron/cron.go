package cron

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&cronRunning{})
	check.Register(&crontabPerms{})
	check.Register(&cronDirPerms{})
	check.Register(&cronAllow{})
	check.Register(&atAllow{})
	check.Register(&suspiciousJobs{})
	check.Register(&userCrontabs{})
}

func svcActive(name string) bool {
	out, err := exec.Command("systemctl", "is-active", name).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// CRON-001
type cronRunning struct{}

func (c *cronRunning) ID() string             { return "CRON-001" }
func (c *cronRunning) Name() string           { return "Cron daemon enabled and running" }
func (c *cronRunning) Category() string       { return "cron" }
func (c *cronRunning) Severity() check.Severity { return check.Low }
func (c *cronRunning) Description() string    { return "Verify cron service is active" }

func (c *cronRunning) Run() check.Result {
	if svcActive("cron") || svcActive("crond") {
		return check.Result{Status: check.Pass, Message: "Cron daemon is active"}
	}
	return check.Result{
		Status: check.Warn, Message: "Cron daemon is not running",
		Remediation: "Enable cron: 'systemctl enable --now cron'",
	}
}

// CRON-002
type crontabPerms struct{}

func (c *crontabPerms) ID() string             { return "CRON-002" }
func (c *crontabPerms) Name() string           { return "/etc/crontab permissions" }
func (c *crontabPerms) Category() string       { return "cron" }
func (c *crontabPerms) Severity() check.Severity { return check.Medium }
func (c *crontabPerms) Description() string    { return "Verify /etc/crontab is 0600 root:root" }

func (c *crontabPerms) Run() check.Result {
	info, err := os.Stat("/etc/crontab")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "/etc/crontab not found"}
	}
	perm := info.Mode().Perm()
	if perm > 0600 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("/etc/crontab has permissions %04o (expected 0600)", perm),
			Remediation: "Fix: chmod 600 /etc/crontab",
		}
	}
	return check.Result{Status: check.Pass, Message: "/etc/crontab permissions are correct"}
}

// CRON-003
type cronDirPerms struct{}

func (c *cronDirPerms) ID() string             { return "CRON-003" }
func (c *cronDirPerms) Name() string           { return "Cron directories permissions" }
func (c *cronDirPerms) Category() string       { return "cron" }
func (c *cronDirPerms) Severity() check.Severity { return check.Medium }
func (c *cronDirPerms) Description() string    { return "Verify cron directories are 0700" }

func (c *cronDirPerms) Run() check.Result {
	dirs := []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	var bad []string
	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm > 0700 {
			bad = append(bad, fmt.Sprintf("%s (%04o)", d, perm))
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "Cron directories too permissive: " + strings.Join(bad, ", "),
			Remediation: "Fix: chmod 700 /etc/cron.{hourly,daily,weekly,monthly}",
		}
	}
	return check.Result{Status: check.Pass, Message: "Cron directories have correct permissions"}
}

// CRON-004
type cronAllow struct{}

func (c *cronAllow) ID() string             { return "CRON-004" }
func (c *cronAllow) Name() string           { return "cron.allow exists, cron.deny removed" }
func (c *cronAllow) Category() string       { return "cron" }
func (c *cronAllow) Severity() check.Severity { return check.Medium }
func (c *cronAllow) Description() string    { return "Verify whitelist approach for cron access" }

func (c *cronAllow) Run() check.Result {
	_, allowErr := os.Stat("/etc/cron.allow")
	_, denyErr := os.Stat("/etc/cron.deny")

	if allowErr == nil && denyErr != nil {
		return check.Result{Status: check.Pass, Message: "cron.allow exists and cron.deny is absent"}
	}

	var issues []string
	if allowErr != nil {
		issues = append(issues, "cron.allow not found")
	}
	if denyErr == nil {
		issues = append(issues, "cron.deny exists (should use whitelist approach)")
	}

	return check.Result{
		Status:      check.Warn,
		Message:     strings.Join(issues, "; "),
		Remediation: "Create /etc/cron.allow with authorized users and remove /etc/cron.deny",
	}
}

// CRON-005
type atAllow struct{}

func (c *atAllow) ID() string             { return "CRON-005" }
func (c *atAllow) Name() string           { return "at.allow exists, at.deny removed" }
func (c *atAllow) Category() string       { return "cron" }
func (c *atAllow) Severity() check.Severity { return check.Medium }
func (c *atAllow) Description() string    { return "Verify whitelist approach for at access" }

func (c *atAllow) Run() check.Result {
	_, allowErr := os.Stat("/etc/at.allow")
	_, denyErr := os.Stat("/etc/at.deny")

	if allowErr == nil && denyErr != nil {
		return check.Result{Status: check.Pass, Message: "at.allow exists and at.deny is absent"}
	}

	var issues []string
	if allowErr != nil {
		issues = append(issues, "at.allow not found")
	}
	if denyErr == nil {
		issues = append(issues, "at.deny exists")
	}

	return check.Result{
		Status: check.Warn, Message: strings.Join(issues, "; "),
		Remediation: "Create /etc/at.allow and remove /etc/at.deny",
	}
}

// CRON-006
type suspiciousJobs struct{}

func (c *suspiciousJobs) ID() string             { return "CRON-006" }
func (c *suspiciousJobs) Name() string           { return "No suspicious cron jobs" }
func (c *suspiciousJobs) Category() string       { return "cron" }
func (c *suspiciousJobs) Severity() check.Severity { return check.High }
func (c *suspiciousJobs) Description() string    { return "Check for cron jobs with network downloads or writable scripts" }

var suspiciousPatterns = []string{"curl ", "wget ", "nc ", "ncat ", "/dev/tcp", "bash -i"}

func (c *suspiciousJobs) Run() check.Result {
	cronDirs := []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	var findings []string

	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			path := dir + "/" + e.Name()
			if scanFileForPatterns(path, suspiciousPatterns) {
				findings = append(findings, path)
			}
		}
	}

	// Check system crontab
	if scanFileForPatterns("/etc/crontab", suspiciousPatterns) {
		findings = append(findings, "/etc/crontab")
	}

	if len(findings) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "Suspicious patterns in cron jobs: " + strings.Join(findings, ", "),
			Remediation: "Review flagged cron jobs for unauthorized network access or commands",
		}
	}
	return check.Result{Status: check.Pass, Message: "No suspicious cron jobs detected"}
}

func scanFileForPatterns(path string, patterns []string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, p := range patterns {
			if strings.Contains(line, p) {
				return true
			}
		}
	}
	return false
}

// CRON-007
type userCrontabs struct{}

func (c *userCrontabs) ID() string             { return "CRON-007" }
func (c *userCrontabs) Name() string           { return "User crontabs reviewed" }
func (c *userCrontabs) Category() string       { return "cron" }
func (c *userCrontabs) Severity() check.Severity { return check.Low }
func (c *userCrontabs) Description() string    { return "List users with crontabs for review" }

func (c *userCrontabs) Run() check.Result {
	entries, err := os.ReadDir("/var/spool/cron/crontabs")
	if err != nil {
		entries, err = os.ReadDir("/var/spool/cron")
		if err != nil {
			return check.Result{Status: check.Pass, Message: "No user crontabs directory found"}
		}
	}

	var users []string
	for _, e := range entries {
		if !e.IsDir() {
			users = append(users, e.Name())
		}
	}

	if len(users) > 0 {
		return check.Result{
			Status:  check.Warn,
			Message: "Users with crontabs: " + strings.Join(users, ", "),
		}
	}
	return check.Result{Status: check.Pass, Message: "No user crontabs found"}
}
