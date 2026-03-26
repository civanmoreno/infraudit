package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

// setupFSRoot creates a temp directory and sets check.FSRoot to it.
func setupFSRoot(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	check.FSRoot = tmp
	t.Cleanup(func() {
		check.FSRoot = ""
		check.ResetCache()
	})
	return tmp
}

// writeFile creates a file under the FSRoot-prefixed path with the given content and mode.
func writeFile(t *testing.T, root, path, content string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to umask; chmod explicitly to ensure exact permissions.
	if err := os.Chmod(full, mode); err != nil {
		t.Fatal(err)
	}
}

// mkDir creates a directory under the FSRoot-prefixed path with the given mode.
func mkDir(t *testing.T, root, path string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(full, 0755); err != nil {
		t.Fatal(err)
	}
	// MkdirAll may not set exact mode due to umask; chmod explicitly.
	if err := os.Chmod(full, mode); err != nil {
		t.Fatal(err)
	}
}

// writeMounts writes a /proc/mounts file with the given content.
func writeMounts(t *testing.T, root, content string) {
	t.Helper()
	writeFile(t, root, "proc/mounts", content, 0644)
}

// --- Home Permissions (FS-006) ---

func TestHomePerms_Restrictive(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "home/testuser", 0700)

	c := &homePerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestHomePerms_WorldReadable(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "home/testuser", 0777)

	c := &homePerms{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestHomePerms_NoHome(t *testing.T) {
	root := setupFSRoot(t)
	// Create /home but leave it empty
	mkDir(t, root, "home", 0755)

	c := &homePerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no user dirs), got %s: %s", r.Status, r.Message)
	}
}

// --- File Permissions (checkFilePerms via filePermEntry) ---

func TestFilePerms_CrontabCorrect(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "etc/cron.hourly", 0700)

	c := &filePermEntry{id: "FS-019", name: "/etc/cron.hourly permissions", path: "/etc/cron.hourly", maxPerm: 0o700}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_CrontabTooPermissive(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "etc/cron.hourly", 0755)

	c := &filePermEntry{id: "FS-019", name: "/etc/cron.hourly permissions", path: "/etc/cron.hourly", maxPerm: 0o700}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_CronDailyCorrect(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "etc/cron.daily", 0700)

	c := &filePermEntry{id: "FS-020", name: "/etc/cron.daily permissions", path: "/etc/cron.daily", maxPerm: 0o700}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_CronDailyTooPermissive(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "etc/cron.daily", 0755)

	c := &filePermEntry{id: "FS-020", name: "/etc/cron.daily permissions", path: "/etc/cron.daily", maxPerm: 0o700}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_CronWeeklyCorrect(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "etc/cron.weekly", 0700)

	c := &filePermEntry{id: "FS-021", path: "/etc/cron.weekly", maxPerm: 0o700}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_SshdConfigCorrect(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PermitRootLogin no\n", 0600)

	c := &filePermEntry{id: "FS-026", path: "/etc/ssh/sshd_config", maxPerm: 0o600}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_SshdConfigTooPermissive(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PermitRootLogin no\n", 0644)

	c := &filePermEntry{id: "FS-026", path: "/etc/ssh/sshd_config", maxPerm: 0o600}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_NotExist(t *testing.T) {
	_ = setupFSRoot(t)
	// File does not exist -- should pass (not-exist is OK)
	c := &filePermEntry{id: "FS-024", path: "/etc/at.allow", maxPerm: 0o640}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS for nonexistent file, got %s: %s", r.Status, r.Message)
	}
}

// --- Mount Options (FS-004) ---

func TestMountOptions_WithRestrictiveOptions(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "tmpfs /tmp tmpfs rw,nodev,nosuid,noexec 0 0\ntmpfs /var/tmp tmpfs rw,nodev,nosuid,noexec 0 0\n/dev/sda2 /home ext4 rw,nodev,nosuid 0 0\n")

	c := &mountOptions{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestMountOptions_MissingOptions(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "tmpfs /tmp tmpfs rw 0 0\n")

	c := &mountOptions{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestMountOptions_NoSeparatePartitions(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "/dev/sda1 / ext4 rw 0 0\n")

	c := &mountOptions{}
	r := c.Run()
	// No separate partitions for /tmp, /var/tmp, /home -- should pass (they are skipped)
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no separate partitions to check), got %s: %s", r.Status, r.Message)
	}
}

// --- /dev/shm Mount (FS-005) ---

func TestDevShmMount_WithOptions(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "tmpfs /dev/shm tmpfs rw,nodev,nosuid,noexec 0 0\n")

	c := &devShmMount{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDevShmMount_MissingOptions(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "tmpfs /dev/shm tmpfs rw 0 0\n")

	c := &devShmMount{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestDevShmMount_NotMounted(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "/dev/sda1 / ext4 rw 0 0\n")

	c := &devShmMount{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Sticky Bit (FS-003) ---

func TestStickyBit_Set(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "tmp", 0777|os.ModeSticky)
	mkDir(t, root, "var/tmp", 0777|os.ModeSticky)

	c := &stickyBit{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestStickyBit_NotSet(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "tmp", 0777)
	mkDir(t, root, "var/tmp", 0777)

	c := &stickyBit{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestStickyBit_PartiallySet(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "tmp", 0777|os.ModeSticky)
	mkDir(t, root, "var/tmp", 0777) // no sticky bit

	c := &stickyBit{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- /tmp Separate Partition (FS-009) ---

func TestTmpPartition_Separate(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "tmpfs /tmp tmpfs rw,nodev,nosuid,noexec 0 0\n")

	c := &tmpPartition{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestTmpPartition_NotSeparate(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "/dev/sda1 / ext4 rw 0 0\n")

	c := &tmpPartition{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Separate Partitions (FS-008) ---

func TestSeparatePartitions_AllPresent(t *testing.T) {
	root := setupFSRoot(t)
	mounts := "/dev/sda1 / ext4 rw 0 0\n" +
		"tmpfs /tmp tmpfs rw 0 0\n" +
		"/dev/sda2 /var ext4 rw 0 0\n" +
		"/dev/sda3 /var/log ext4 rw 0 0\n" +
		"/dev/sda4 /var/log/audit ext4 rw 0 0\n" +
		"/dev/sda5 /var/tmp ext4 rw 0 0\n" +
		"/dev/sda6 /home ext4 rw 0 0\n"
	writeMounts(t, root, mounts)

	c := &separatePartitions{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSeparatePartitions_SomeMissing(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n")

	c := &separatePartitions{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- User Dot Files (FS-032, FS-033, FS-034, FS-035) ---

func TestNoForwardFiles_NoFiles(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n", 0644)
	mkDir(t, root, "home/john", 0750)

	c := &noForwardFiles{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestNoForwardFiles_WithForwardFile(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n", 0644)
	mkDir(t, root, "home/john", 0750)
	writeFile(t, root, "home/john/.forward", "user@example.com\n", 0644)

	c := &noForwardFiles{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestNoNetrcFiles_WithNetrcFile(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n", 0644)
	mkDir(t, root, "home/john", 0750)
	writeFile(t, root, "home/john/.netrc", "machine example.com\n", 0644)

	c := &noNetrcFiles{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestNoRhostsFiles_NoFiles(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n", 0644)
	mkDir(t, root, "home/john", 0750)

	c := &noRhostsFiles{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestUserDotFiles_NoWritable(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n", 0644)
	mkDir(t, root, "home/john", 0750)
	writeFile(t, root, "home/john/.bashrc", "# bashrc\n", 0600)

	c := &userDotFiles{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestUserDotFiles_WorldWritable(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n", 0644)
	mkDir(t, root, "home/john", 0750)
	writeFile(t, root, "home/john/.bashrc", "# bashrc\n", 0666)

	c := &userDotFiles{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- /home nodev (FS-017) ---

func TestHomeNodev_WithNodev(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "/dev/sda2 /home ext4 rw,nodev 0 0\n")

	c := &homeNodev{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestHomeNodev_WithoutNodev(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "/dev/sda2 /home ext4 rw 0 0\n")

	c := &homeNodev{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestHomeNodev_NotSeparate(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "/dev/sda1 / ext4 rw 0 0\n")

	c := &homeNodev{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- /var/tmp mount options (FS-010) ---

func TestVarTmpMount_WithOptions(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "tmpfs /var/tmp tmpfs rw,nodev,nosuid,noexec 0 0\n")

	c := &varTmpMount{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestVarTmpMount_MissingOptions(t *testing.T) {
	root := setupFSRoot(t)
	writeMounts(t, root, "tmpfs /var/tmp tmpfs rw 0 0\n")

	c := &varTmpMount{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- opasswd permissions (FS-018) ---

func TestOpasswdPerms_Correct(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/opasswd", "", 0600)

	c := &opasswdPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestOpasswdPerms_TooPermissive(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/opasswd", "", 0644)

	c := &opasswdPerms{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}
