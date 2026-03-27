package rlimit

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

// writeFile creates a file under the FSRoot-prefixed path with the given content.
func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

// --- Metadata tests ---

func TestMetadata(t *testing.T) {
	checks := []struct {
		c    check.Check
		id   string
		name string
		cat  string
		sev  check.Severity
	}{
		{&openFiles{}, "RLIM-001", "Open files limit is reasonable", "rlimit", check.Low},
		{&maxProcs{}, "RLIM-002", "Max user processes limit set", "rlimit", check.Medium},
		{&stackSize{}, "RLIM-003", "Stack size limits configured", "rlimit", check.Low},
		{&wildcardUnlimited{}, "RLIM-004", "No wildcard unlimited entries", "rlimit", check.Medium},
		{&rootDisk{}, "RLIM-005", "Root filesystem space below 85%", "rlimit", check.High},
		{&varDisk{}, "RLIM-006", "/var, /var/log, /tmp have sufficient space", "rlimit", check.Medium},
		{&inodeUsage{}, "RLIM-007", "Inode usage is not exhausted", "rlimit", check.High},
	}

	for _, tc := range checks {
		t.Run(tc.id, func(t *testing.T) {
			if tc.c.ID() != tc.id {
				t.Errorf("ID: got %s, want %s", tc.c.ID(), tc.id)
			}
			if tc.c.Name() != tc.name {
				t.Errorf("Name: got %s, want %s", tc.c.Name(), tc.name)
			}
			if tc.c.Category() != tc.cat {
				t.Errorf("Category: got %s, want %s", tc.c.Category(), tc.cat)
			}
			if tc.c.Severity() != tc.sev {
				t.Errorf("Severity: got %v, want %v", tc.c.Severity(), tc.sev)
			}
			if tc.c.Description() == "" {
				t.Error("Description should not be empty")
			}
		})
	}
}

// --- RLIM-001: Open files limit ---

func TestOpenFiles_HighValue(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/fs/file-max", "262144\n")

	c := &openFiles{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestOpenFiles_LowValue(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "proc/sys/fs/file-max", "1024\n")

	c := &openFiles{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestOpenFiles_Missing(t *testing.T) {
	setupFSRoot(t) // empty tmpdir

	c := &openFiles{}
	r := c.Run()
	if r.Status != check.Error {
		t.Errorf("expected ERROR, got %s: %s", r.Status, r.Message)
	}
}

// --- RLIM-002: Max user processes ---

func TestMaxProcs_NprocInLimitsConf(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "* hard nproc 4096\n")

	c := &maxProcs{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestMaxProcs_NprocInLimitsD(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "# empty\n")
	writeFile(t, root, "etc/security/limits.d/90-nproc.conf", "* hard nproc 4096\n")

	c := &maxProcs{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestMaxProcs_NotConfigured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "# nothing\n")

	c := &maxProcs{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestMaxProcs_MissingFile(t *testing.T) {
	setupFSRoot(t)

	c := &maxProcs{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- RLIM-003: Stack size ---

func TestStackSize_Configured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "* hard stack 8192\n")

	c := &stackSize{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestStackSize_NotConfigured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "# nothing\n")

	c := &stackSize{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- RLIM-004: Wildcard unlimited ---

func TestWildcardUnlimited_Found(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "* hard nofile unlimited\n")

	c := &wildcardUnlimited{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestWildcardUnlimited_FoundInLimitsD(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "# clean\n")
	writeFile(t, root, "etc/security/limits.d/99-wild.conf", "* hard nofile unlimited\n")

	c := &wildcardUnlimited{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestWildcardUnlimited_Clean(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "# safe\nroot hard nofile 65536\n")

	c := &wildcardUnlimited{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestWildcardUnlimited_CommentedOut(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/security/limits.conf", "# * hard nofile unlimited\n")

	c := &wildcardUnlimited{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}
