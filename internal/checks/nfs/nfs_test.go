package nfs

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

// --- NFS-001: nfsExports ---

func TestNfsExports_Pass_RootSquash(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/exports", "/data 192.168.1.0/24(rw,root_squash,sync)\n", 0644)

	c := &nfsExports{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestNfsExports_Fail_NoRootSquash(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/exports", "/data 192.168.1.0/24(rw,no_root_squash,sync)\n", 0644)

	c := &nfsExports{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestNfsExports_Pass_NoFile(t *testing.T) {
	_ = setupFSRoot(t)

	c := &nfsExports{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no exports file), got %s: %s", r.Status, r.Message)
	}
}

// --- NFS-003: sambaConfig ---

func TestSambaConfig_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/samba/smb.conf", "[global]\n   guest ok = no\n   workgroup = WORKGROUP\n", 0644)

	c := &sambaConfig{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSambaConfig_Warn_GuestYes(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/samba/smb.conf", "[share]\n   guest ok = yes\n   path = /data\n", 0644)

	c := &sambaConfig{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSambaConfig_Pass_NoFile(t *testing.T) {
	_ = setupFSRoot(t)

	c := &sambaConfig{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no smb.conf), got %s: %s", r.Status, r.Message)
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
		{&nfsExports{}, "NFS-001", "NFS exports reviewed", "nfs", check.High},
		{&nfsv3Disabled{}, "NFS-002", "NFSv3 disabled if NFSv4 available", "nfs", check.Medium},
		{&sambaConfig{}, "NFS-003", "Samba config reviewed", "nfs", check.Medium},
		{&rpcbindDisabled{}, "NFS-004", "rpcbind disabled if NFS not in use", "nfs", check.Medium},
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
