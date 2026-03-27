package backup

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

func mkDir(t *testing.T, root, path string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(full, 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		t.Fatal(err)
	}
}

// --- BAK-003: backupPerms ---

func TestBackupPerms_Pass(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "var/backups", 0700)

	c := &backupPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestBackupPerms_Warn_WorldReadable(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "var/backups", 0777)

	c := &backupPerms{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Metadata tests for all 4 checks ---

func TestMetadata(t *testing.T) {
	tests := []struct {
		c        check.Check
		id       string
		name     string
		cat      string
		severity check.Severity
	}{
		{&backupSchedule{}, "BAK-001", "Backup schedule exists and ran recently", "backup", check.High},
		{&backupEncrypted{}, "BAK-002", "Backups are encrypted", "backup", check.Medium},
		{&backupPerms{}, "BAK-003", "Backup files not world-readable", "backup", check.High},
		{&backupOffsite{}, "BAK-004", "Off-site/off-host backup exists", "backup", check.Medium},
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
