package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

// setupFSRoot creates a temp directory and sets check.FSRoot to it.
// Returns the temp dir path. Registers cleanup to reset FSRoot and cache.
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
}

// --- SSH Root Login (AUTH-001) ---

func TestSSHRootLogin_PermitYes(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PermitRootLogin yes\n", 0644)

	c := &sshRootLogin{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHRootLogin_PermitNo(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PermitRootLogin no\n", 0644)

	c := &sshRootLogin{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHRootLogin_NotSet(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "# nothing relevant\n", 0644)

	c := &sshRootLogin{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- SSH Password Auth (AUTH-002) ---

func TestSSHPasswordAuth_Yes(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PasswordAuthentication yes\n", 0644)

	c := &sshPasswordAuth{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHPasswordAuth_No(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PasswordAuthentication no\n", 0644)

	c := &sshPasswordAuth{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHPasswordAuth_NotSet(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "# only comments\n", 0644)

	c := &sshPasswordAuth{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Sudoers NOPASSWD (AUTH-006) ---

func TestSudoersNopasswd_WithNopasswd(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers", "admin ALL=(ALL) NOPASSWD: ALL\n", 0440)

	c := &sudoersNopasswd{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSudoersNopasswd_Clean(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n", 0440)

	c := &sudoersNopasswd{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSudoersNopasswd_DropIn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n", 0440)
	writeFile(t, root, "etc/sudoers.d/custom", "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n", 0440)

	c := &sudoersNopasswd{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- UID Zero (AUTH-003) ---

func TestUIDZero_OnlyRoot(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &uidZero{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestUIDZero_ExtraUID0(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0:toor:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &uidZero{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Empty Password (AUTH-004) ---

func TestEmptyPassword_NormalHashes(t *testing.T) {
	root := setupFSRoot(t)
	shadow := "root:$6$rounds=5000$salt$hash:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n"
	writeFile(t, root, "etc/shadow", shadow, 0640)

	c := &emptyPassword{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestEmptyPassword_EmptyHash(t *testing.T) {
	root := setupFSRoot(t)
	shadow := "root:$6$rounds=5000$salt$hash:19000:0:99999:7:::\nbaduser::19000:0:99999:7:::\n"
	writeFile(t, root, "etc/shadow", shadow, 0640)

	c := &emptyPassword{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- System Shell (AUTH-005) ---

func TestSystemShell_AllNologin(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &systemShell{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSystemShell_SystemAccountWithBash(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/bash\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &systemShell{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestSystemShell_HighUIDIgnored(t *testing.T) {
	root := setupFSRoot(t)
	// UID >= 1000 users are skipped even with login shells
	passwd := "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &systemShell{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- Sensitive File Permissions (AUTH-007) ---

func TestFilePerms_Correct(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0644)
	writeFile(t, root, "etc/shadow", "root:$6$hash:19000:0:99999:7:::\n", 0640)
	writeFile(t, root, "etc/group", "root:x:0:\n", 0644)

	c := &sensitiveFilePerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_TooPermissive(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0666)
	writeFile(t, root, "etc/shadow", "root:$6$hash:19000:0:99999:7:::\n", 0644)
	writeFile(t, root, "etc/group", "root:x:0:\n", 0644)

	c := &sensitiveFilePerms{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestFilePerms_ShadowWorldReadable(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0644)
	writeFile(t, root, "etc/shadow", "root:$6$hash:19000:0:99999:7:::\n", 0644)
	writeFile(t, root, "etc/group", "root:x:0:\n", 0644)

	c := &sensitiveFilePerms{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL for shadow 0644 > 0640, got %s: %s", r.Status, r.Message)
	}
}

// --- PAM Wheel (AUTH-008) ---

func TestPamWheel_Restricted(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/pam.d/su", "auth required pam_wheel.so use_uid\n", 0644)

	c := &pamWheel{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPamWheel_NotRestricted(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/pam.d/su", "# auth required pam_wheel.so use_uid\nauth sufficient pam_rootok.so\n", 0644)

	c := &pamWheel{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Default Umask (AUTH-009) ---

func TestDefaultUmask_Restrictive(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/login.defs", "UMASK 027\n", 0644)

	c := &defaultUmask{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDefaultUmask_TooPermissive(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/login.defs", "UMASK 022\n", 0644)

	c := &defaultUmask{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Shell Timeout (AUTH-010) ---

func TestShellTimeout_Configured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/profile", "TMOUT=900\nreadonly TMOUT\nexport TMOUT\n", 0644)

	c := &shellTimeout{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestShellTimeout_NotConfigured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/profile", "# nothing relevant\n", 0644)

	c := &shellTimeout{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Legacy Entries (AUTH-011 to AUTH-013) ---

func TestLegacyPasswd_Clean(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0644)

	c := &legacyEntry{id: "AUTH-011", name: "No legacy + in /etc/passwd", file: "/etc/passwd"}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLegacyPasswd_WithLegacy(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n+::0:0:::\n", 0644)

	c := &legacyEntry{id: "AUTH-011", name: "No legacy + in /etc/passwd", file: "/etc/passwd"}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestLegacyShadow_Clean(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/shadow", "root:$6$hash:19000:0:99999:7:::\n", 0640)

	c := &legacyEntry{id: "AUTH-012", name: "No legacy + in /etc/shadow", file: "/etc/shadow"}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLegacyGroup_WithLegacy(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/group", "root:x:0:\n+:::\n", 0644)

	c := &legacyEntry{id: "AUTH-013", name: "No legacy + in /etc/group", file: "/etc/group"}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Home Dirs Exist (AUTH-014) ---

func TestHomeDirsExist_AllExist(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)
	// Create john's home directory
	if err := os.MkdirAll(filepath.Join(root, "home/john"), 0750); err != nil {
		t.Fatal(err)
	}

	c := &homeDirsExist{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestHomeDirsExist_MissingHome(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)
	// Do NOT create john's home directory

	c := &homeDirsExist{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Duplicate UIDs (AUTH-017) ---

func TestDuplicateUIDs_NoDuplicates(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\njohn:x:1000:1000:John:/home/john:/bin/bash\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &duplicateCheck{id: "AUTH-017", name: "No duplicate UIDs", desc: "Ensure no duplicate UIDs exist", field: "uid"}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDuplicateUIDs_WithDuplicate(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\njane:x:1000:1000:Jane:/home/jane:/bin/bash\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &duplicateCheck{id: "AUTH-017", name: "No duplicate UIDs", desc: "Ensure no duplicate UIDs exist", field: "uid"}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Duplicate Users (AUTH-019) ---

func TestDuplicateUsers_NoDuplicates(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &duplicateCheck{id: "AUTH-019", name: "No duplicate user names", desc: "Ensure no duplicate user names exist", field: "user"}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDuplicateUsers_WithDuplicate(t *testing.T) {
	root := setupFSRoot(t)
	passwd := "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\njohn:x:1001:1001:John2:/home/john2:/bin/bash\n"
	writeFile(t, root, "etc/passwd", passwd, 0644)

	c := &duplicateCheck{id: "AUTH-019", name: "No duplicate user names", desc: "Ensure no duplicate user names exist", field: "user"}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Duplicate GIDs (AUTH-018) ---

func TestDuplicateGIDs_NoDuplicates(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/group", "root:x:0:\ndaemon:x:1:\njohn:x:1000:\n", 0644)

	c := &duplicateCheck{id: "AUTH-018", name: "No duplicate GIDs", desc: "Ensure no duplicate GIDs exist", field: "gid"}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDuplicateGIDs_WithDuplicate(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/group", "root:x:0:\nstaff:x:100:\nengineers:x:100:\n", 0644)

	c := &duplicateCheck{id: "AUTH-018", name: "No duplicate GIDs", desc: "Ensure no duplicate GIDs exist", field: "gid"}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Duplicate Groups (AUTH-020) ---

func TestDuplicateGroups_WithDuplicate(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/group", "root:x:0:\nstaff:x:100:\nstaff:x:200:\n", 0644)

	c := &duplicateCheck{id: "AUTH-020", name: "No duplicate group names", desc: "Ensure no duplicate group names exist", field: "group"}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Groups in Passwd exist in Group (AUTH-021) ---

func TestGroupsInPasswd_AllExist(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:1000:John:/home/john:/bin/bash\n", 0644)
	writeFile(t, root, "etc/group", "root:x:0:\njohn:x:1000:\n", 0644)

	c := &groupsInPasswd{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestGroupsInPasswd_MissingGroup(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\njohn:x:1000:9999:John:/home/john:/bin/bash\n", 0644)
	writeFile(t, root, "etc/group", "root:x:0:\njohn:x:1000:\n", 0644)

	c := &groupsInPasswd{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Shadow Group Empty (AUTH-022) ---

func TestShadowGroupEmpty_NoMembers(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/group", "root:x:0:\nshadow:x:42:\n", 0644)

	c := &shadowGroupEmpty{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestShadowGroupEmpty_WithMembers(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/group", "root:x:0:\nshadow:x:42:john,jane\n", 0644)

	c := &shadowGroupEmpty{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestShadowGroupEmpty_NoShadowGroup(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/group", "root:x:0:\nusers:x:100:\n", 0644)

	c := &shadowGroupEmpty{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}
