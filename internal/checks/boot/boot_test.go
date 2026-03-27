package boot

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

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

func writeFile(t *testing.T, root, path, content string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		t.Fatal(err)
	}
}

// --- BOOT-001: grubPassword ---

func TestGrubPassword_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "boot/grub/grub.cfg", "password_pbkdf2 admin grub.pbkdf2.sha512...\n", 0600)

	c := &grubPassword{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestGrubPassword_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "boot/grub/grub.cfg", "menuentry 'Ubuntu' {\n}\n", 0600)

	c := &grubPassword{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- BOOT-002: grubPerms ---

func TestGrubPerms_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "boot/grub/grub.cfg", "some config\n", 0600)

	c := &grubPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestGrubPerms_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "boot/grub/grub.cfg", "some config\n", 0644)

	c := &grubPerms{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- BOOT-004: singleUserAuth ---

func TestSingleUserAuth_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/shadow", "root:$6$rounds=5000$saltsalt$hashhashhash:19000:0:99999:7:::\n", 0640)

	c := &singleUserAuth{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSingleUserAuth_Fail_NoPassword(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/shadow", "root:!:19000:0:99999:7:::\n", 0640)

	c := &singleUserAuth{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Metadata tests for all 8 checks ---

func TestMetadata(t *testing.T) {
	tests := []struct {
		c        check.Check
		id       string
		name     string
		cat      string
		severity check.Severity
	}{
		{&grubPassword{}, "BOOT-001", "GRUB bootloader password set", "boot", check.High},
		{&grubPerms{}, "BOOT-002", "Bootloader config permissions", "boot", check.High},
		{&secureBoot{}, "BOOT-003", "UEFI Secure Boot enabled", "boot", check.Medium},
		{&singleUserAuth{}, "BOOT-004", "Single-user mode requires authentication", "boot", check.High},
		{&macInstalled{}, "BOOT-005", "SELinux or AppArmor installed and enabled", "boot", check.High},
		{&macEnforcing{}, "BOOT-006", "MAC in enforcing mode", "boot", check.High},
		{&unconfinedProcs{}, "BOOT-007", "No unconfined processes", "boot", check.Medium},
		{&macDenials{}, "BOOT-008", "No MAC denials in logs", "boot", check.Low},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if tt.c.ID() != tt.id {
				t.Errorf("ID: got %q, want %q", tt.c.ID(), tt.id)
			}
			if tt.c.Name() != tt.name {
				t.Errorf("Name: got %q, want %q", tt.c.Name(), tt.name)
			}
			if tt.c.Category() != tt.cat {
				t.Errorf("Category: got %q, want %q", tt.c.Category(), tt.cat)
			}
			if tt.c.Severity() != tt.severity {
				t.Errorf("Severity: got %v, want %v", tt.c.Severity(), tt.severity)
			}
			if tt.c.Description() == "" {
				t.Error("Description should not be empty")
			}
		})
	}
}
