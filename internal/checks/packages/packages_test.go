package packages

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
		{&securityUpdates{}, "PKG-001", "No pending security updates", "packages", check.High},
		{&repoHTTPS{}, "PKG-002", "Package repositories use HTTPS", "packages", check.Medium},
		{&kernelUpdate{}, "PKG-003", "Kernel is up to date", "packages", check.High},
		{&autoUpdates{}, "PKG-004", "Automatic security updates enabled", "packages", check.Medium},
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

// --- PKG-002: Repo HTTPS ---

func TestRepoHTTPS_AllHTTPS(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/apt/sources.list", "deb https://archive.ubuntu.com/ubuntu focal main\n")

	c := &repoHTTPS{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRepoHTTPS_InsecureMainList(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/apt/sources.list", "deb http://archive.ubuntu.com/ubuntu focal main\n")

	c := &repoHTTPS{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestRepoHTTPS_InsecureInSourcesListD(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/apt/sources.list", "# empty\n")
	writeFile(t, root, "etc/apt/sources.list.d/custom.list", "deb http://ppa.launchpad.net/foo focal main\n")

	c := &repoHTTPS{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestRepoHTTPS_InsecureYumRepo(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/yum.repos.d/centos.repo", "[base]\nbaseurl=http://mirror.centos.org/centos/7/os/x86_64/\n")

	c := &repoHTTPS{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestRepoHTTPS_SecureYumRepo(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/yum.repos.d/centos.repo", "[base]\nbaseurl=https://mirror.centos.org/centos/7/os/x86_64/\n")

	c := &repoHTTPS{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRepoHTTPS_CommentedHTTP(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/apt/sources.list", "# deb http://old.example.com/ubuntu focal main\n")

	c := &repoHTTPS{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRepoHTTPS_NoFiles(t *testing.T) {
	setupFSRoot(t) // empty tmpdir

	c := &repoHTTPS{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- PKG-003: Kernel update ---

func TestKernelUpdate_RebootRequired(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "var/run/reboot-required", "*** System restart required ***\n")

	c := &kernelUpdate{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelUpdate_NoRebootRequired(t *testing.T) {
	setupFSRoot(t)

	c := &kernelUpdate{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}
