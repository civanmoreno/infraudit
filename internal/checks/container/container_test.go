package container

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
		{&dockerDetect{}, "CTR-001", "Docker/Podman detected", "container", check.Info},
		{&dockerDaemonConfig{}, "CTR-002", "Docker daemon configuration reviewed", "container", check.Medium},
		{&dockerSocketPerms{}, "CTR-003", "Docker socket permissions restricted", "container", check.High},
		{&rootContainers{}, "CTR-004", "No containers running as root", "container", check.High},
		{&privilegedContainers{}, "CTR-005", "No privileged containers", "container", check.Critical},
		{&resourceLimits{}, "CTR-006", "Container resource limits set", "container", check.Medium},
		{&contentTrust{}, "CTR-007", "Docker content trust enabled", "container", check.Medium},
		{&iccDisabled{}, "CTR-008", "Inter-container communication restricted", "container", check.Medium},
		{&readonlyRootfs{}, "CTR-009", "Read-only root filesystem in containers", "container", check.Low},
		{&loggingDriver{}, "CTR-010", "Docker logging driver configured", "container", check.Low},
		{&trustedRegistries{}, "CTR-011", "Images from trusted registries", "container", check.Medium},
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

// --- CTR-002: Docker daemon config ---

func TestDockerDaemonConfig_ValidJSON(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/docker/daemon.json", `{"storage-driver":"overlay2"}`)

	c := &dockerDaemonConfig{}
	r := c.Run()
	// Docker not installed in test env, so it returns pass/skipped.
	// If docker IS on PATH, it should parse the file.
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDockerDaemonConfig_MissingFile(t *testing.T) {
	setupFSRoot(t) // empty tmpdir, no daemon.json

	c := &dockerDaemonConfig{}
	r := c.Run()
	// Without docker on PATH: pass (skipped). With docker: warn (missing file).
	if r.Status != check.Pass && r.Status != check.Warn {
		t.Errorf("expected PASS or WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestDockerDaemonConfig_InvalidJSON(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/docker/daemon.json", `{invalid`)

	c := &dockerDaemonConfig{}
	r := c.Run()
	// Without docker: pass (skipped). With docker: warn (invalid json).
	if r.Status != check.Pass && r.Status != check.Warn {
		t.Errorf("expected PASS or WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- CTR-003: Docker socket perms ---

func TestDockerSocketPerms_WorldAccessible(t *testing.T) {
	root := setupFSRoot(t)
	sock := filepath.Join(root, "var/run/docker.sock")
	if err := os.MkdirAll(filepath.Dir(sock), 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, nil, 0666); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	c := &dockerSocketPerms{}
	r := c.Run()
	// Without docker: pass (skipped). With docker: fail (world-accessible).
	if r.Status != check.Pass && r.Status != check.Fail {
		t.Errorf("expected PASS or FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestDockerSocketPerms_Restricted(t *testing.T) {
	root := setupFSRoot(t)
	sock := filepath.Join(root, "var/run/docker.sock")
	if err := os.MkdirAll(filepath.Dir(sock), 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, nil, 0660); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	c := &dockerSocketPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDockerSocketPerms_Missing(t *testing.T) {
	setupFSRoot(t)

	c := &dockerSocketPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- CTR-008: ICC disabled ---

func TestICCDisabled_ICCFalse(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/docker/daemon.json", `{"icc": false}`)

	c := &iccDisabled{}
	r := c.Run()
	// Without docker: pass (skipped). With docker: pass (icc disabled).
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestICCDisabled_ICCTrue(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/docker/daemon.json", `{"icc": true}`)

	c := &iccDisabled{}
	r := c.Run()
	// Without docker: pass (skipped). With docker: warn.
	if r.Status != check.Pass && r.Status != check.Warn {
		t.Errorf("expected PASS or WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestICCDisabled_NoDaemonJSON(t *testing.T) {
	setupFSRoot(t)

	c := &iccDisabled{}
	r := c.Run()
	// Without docker: pass (skipped). With docker: warn.
	if r.Status != check.Pass && r.Status != check.Warn {
		t.Errorf("expected PASS or WARN, got %s: %s", r.Status, r.Message)
	}
}
