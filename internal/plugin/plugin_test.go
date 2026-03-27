package plugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

func setup(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	check.FSRoot = tmp
	t.Cleanup(func() {
		check.FSRoot = ""
		check.Reset()
	})
	return tmp
}

func writePlugin(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

func TestLoadDir_SingleCheck(t *testing.T) {
	tmp := setup(t)
	dir := filepath.Join(tmp, "etc", "infraudit", "checks.d")
	writePlugin(t, dir, "custom.yaml", `
id: CUSTOM-001
name: SSH banner exists
category: custom
severity: medium
description: Ensure SSH login banner is present
remediation: Create /etc/issue with a warning message
rule:
  type: file_exists
  path: /etc/issue
`)
	// Create the file that the check looks for
	if err := os.MkdirAll(filepath.Join(tmp, "etc"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(tmp, "etc", "issue"), []byte("Warning"), 0o644) //nolint:gosec,errcheck

	loaded, errs := LoadDir("/etc/infraudit/checks.d")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if loaded != 1 {
		t.Fatalf("loaded = %d, want 1", loaded)
	}

	c := check.ByID("CUSTOM-001")
	if c == nil {
		t.Fatal("check CUSTOM-001 not registered")
	}
	if c.Name() != "SSH banner exists" {
		t.Errorf("Name = %q, want 'SSH banner exists'", c.Name())
	}
	if c.Category() != "custom" {
		t.Errorf("Category = %q, want 'custom'", c.Category())
	}

	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("Status = %v, want PASS (file exists)", r.Status)
	}
}

func TestLoadDir_MultipleChecks(t *testing.T) {
	tmp := setup(t)
	dir := filepath.Join(tmp, "etc", "infraudit", "checks.d")
	writePlugin(t, dir, "multi.yaml", `
checks:
  - id: MULTI-001
    name: Check one
    category: custom
    severity: low
    description: First check
    rule:
      type: file_exists
      path: /tmp/test
  - id: MULTI-002
    name: Check two
    category: custom
    severity: high
    description: Second check
    rule:
      type: file_missing
      path: /tmp/bad
`)

	loaded, errs := LoadDir("/etc/infraudit/checks.d")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if loaded != 2 {
		t.Fatalf("loaded = %d, want 2", loaded)
	}
}

func TestLoadDir_NonexistentDir(t *testing.T) {
	setup(t)
	loaded, errs := LoadDir("/nonexistent/path")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors for nonexistent dir: %v", errs)
	}
	if loaded != 0 {
		t.Fatalf("loaded = %d, want 0", loaded)
	}
}

func TestLoadDir_InvalidYAML(t *testing.T) {
	tmp := setup(t)
	dir := filepath.Join(tmp, "etc", "infraudit", "checks.d")
	writePlugin(t, dir, "bad.yaml", `
id: BAD-001
name: Missing fields
category: custom
severity: medium
description: test
rule:
  type: unknown_type
  path: /tmp
`)

	_, errs := LoadDir("/etc/infraudit/checks.d")
	if len(errs) == 0 {
		t.Fatal("expected validation error for unknown rule type")
	}
}

func TestValidation_MissingID(t *testing.T) {
	err := validate(Definition{Name: "x", Category: "x", Severity: "low", Rule: Rule{Type: "file_exists", Path: "/x"}})
	if err == nil || err.Error() != "missing id" {
		t.Errorf("expected 'missing id', got %v", err)
	}
}

func TestValidation_MissingName(t *testing.T) {
	err := validate(Definition{ID: "X-001", Category: "x", Severity: "low", Rule: Rule{Type: "file_exists", Path: "/x"}})
	if err == nil || err.Error() != "missing name" {
		t.Errorf("expected 'missing name', got %v", err)
	}
}

func TestValidation_InvalidSeverity(t *testing.T) {
	err := validate(Definition{ID: "X-001", Name: "x", Category: "x", Severity: "mega", Rule: Rule{Type: "file_exists", Path: "/x"}})
	if err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestValidation_MissingRulePath(t *testing.T) {
	err := validate(Definition{ID: "X-001", Name: "x", Category: "x", Severity: "low", Rule: Rule{Type: "file_exists"}})
	if err == nil {
		t.Error("expected error for missing path")
	}
}

func TestValidation_InvalidPattern(t *testing.T) {
	err := validate(Definition{ID: "X-001", Name: "x", Category: "x", Severity: "low", Rule: Rule{Type: "file_contains", Path: "/x", Pattern: "[invalid"}})
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestValidation_CommandMissingExpect(t *testing.T) {
	err := validate(Definition{ID: "X-001", Name: "x", Category: "x", Severity: "low", Rule: Rule{Type: "command", Command: "echo"}})
	if err == nil {
		t.Error("expected error for command missing expect")
	}
}

func TestRunFileExists_Pass(t *testing.T) {
	tmp := setup(t)
	os.MkdirAll(filepath.Join(tmp, "etc"), 0o755)                        //nolint:gosec,errcheck
	os.WriteFile(filepath.Join(tmp, "etc", "test"), []byte("ok"), 0o644) //nolint:gosec,errcheck

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "file_exists", Path: "/etc/test"},
	})

	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("Status = %v, want PASS", r.Status)
	}
}

func TestRunFileExists_Fail(t *testing.T) {
	setup(t)

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test", Remediation: "create the file",
		Rule: Rule{Type: "file_exists", Path: "/etc/nonexistent"},
	})

	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("Status = %v, want FAIL", r.Status)
	}
	if r.Remediation != "create the file" {
		t.Errorf("Remediation = %q, want 'create the file'", r.Remediation)
	}
}

func TestRunFileMissing_Pass(t *testing.T) {
	setup(t)

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "file_missing", Path: "/etc/nonexistent"},
	})

	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("Status = %v, want PASS", r.Status)
	}
}

func TestRunFileContains_Pass(t *testing.T) {
	tmp := setup(t)
	os.MkdirAll(filepath.Join(tmp, "etc"), 0o755)                                                 //nolint:gosec,errcheck
	os.WriteFile(filepath.Join(tmp, "etc", "sshd_config"), []byte("PermitRootLogin no\n"), 0o644) //nolint:gosec,errcheck

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "file_contains", Path: "/etc/sshd_config", Pattern: "PermitRootLogin\\s+no"},
	})

	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("Status = %v, want PASS", r.Status)
	}
}

func TestRunFileContains_Fail(t *testing.T) {
	tmp := setup(t)
	os.MkdirAll(filepath.Join(tmp, "etc"), 0o755)                                                  //nolint:gosec,errcheck
	os.WriteFile(filepath.Join(tmp, "etc", "sshd_config"), []byte("PermitRootLogin yes\n"), 0o644) //nolint:gosec,errcheck

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "file_contains", Path: "/etc/sshd_config", Pattern: "PermitRootLogin\\s+no"},
	})

	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("Status = %v, want FAIL", r.Status)
	}
}

func TestRunFileNotContains_Pass(t *testing.T) {
	tmp := setup(t)
	os.MkdirAll(filepath.Join(tmp, "etc"), 0o755)                                           //nolint:gosec,errcheck
	os.WriteFile(filepath.Join(tmp, "etc", "config"), []byte("safe_setting=true\n"), 0o644) //nolint:gosec,errcheck

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "file_not_contains", Path: "/etc/config", Pattern: "password="},
	})

	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("Status = %v, want PASS", r.Status)
	}
}

func TestRunFilePerms_Pass(t *testing.T) {
	tmp := setup(t)
	path := filepath.Join(tmp, "etc", "secret")
	os.MkdirAll(filepath.Join(tmp, "etc"), 0o755) //nolint:gosec,errcheck
	os.WriteFile(path, []byte("data"), 0o600)     //nolint:gosec,errcheck
	os.Chmod(path, 0o600)                         //nolint:gosec,errcheck

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "file_perms", Path: "/etc/secret", MaxPerm: "0600"},
	})

	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("Status = %v, want PASS", r.Status)
	}
}

func TestRunFilePerms_Fail(t *testing.T) {
	tmp := setup(t)
	path := filepath.Join(tmp, "etc", "secret")
	os.MkdirAll(filepath.Join(tmp, "etc"), 0o755) //nolint:gosec,errcheck
	os.WriteFile(path, []byte("data"), 0o644)     //nolint:gosec,errcheck
	os.Chmod(path, 0o644)                         //nolint:gosec,errcheck

	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "file_perms", Path: "/etc/secret", MaxPerm: "0600"},
	})

	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("Status = %v, want FAIL", r.Status)
	}
}

func TestRunCommand_Pass(t *testing.T) {
	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "command", Command: "echo", Args: []string{"hello world"}, Expect: "hello"},
	})

	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("Status = %v, want PASS", r.Status)
	}
}

func TestRunCommand_Fail(t *testing.T) {
	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test", Remediation: "fix it",
		Rule: Rule{Type: "command", Command: "echo", Args: []string{"hello"}, Expect: "goodbye"},
	})

	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("Status = %v, want FAIL", r.Status)
	}
}

func TestRunCommand_ExpectFail(t *testing.T) {
	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test",
		Rule:        Rule{Type: "command", Command: "echo", Args: []string{"error found"}, ExpectFail: "error"},
	})

	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("Status = %v, want FAIL (unwanted pattern found)", r.Status)
	}
}

func TestOSAware(t *testing.T) {
	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test", OS: []string{"debian", "redhat"},
		Rule: Rule{Type: "file_exists", Path: "/tmp"},
	})

	got := c.SupportedOS()
	if len(got) != 2 || got[0] != "debian" || got[1] != "redhat" {
		t.Errorf("SupportedOS = %v, want [debian redhat]", got)
	}
}

func TestInitAware(t *testing.T) {
	c := newPluginCheck(Definition{
		ID: "T-001", Name: "test", Category: "test", Severity: "low",
		Description: "test", Init: "systemd",
		Rule: Rule{Type: "file_exists", Path: "/tmp"},
	})

	if c.RequiredInit() != "systemd" {
		t.Errorf("RequiredInit = %q, want 'systemd'", c.RequiredInit())
	}
}

func TestSkipsNonYAMLFiles(t *testing.T) {
	tmp := setup(t)
	dir := filepath.Join(tmp, "etc", "infraudit", "checks.d")
	writePlugin(t, dir, "readme.txt", "not a yaml file")
	writePlugin(t, dir, "valid.yaml", `
id: SKIP-001
name: test
category: custom
severity: low
description: test
rule:
  type: file_missing
  path: /nonexistent
`)

	loaded, errs := LoadDir("/etc/infraudit/checks.d")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if loaded != 1 {
		t.Fatalf("loaded = %d, want 1 (should skip .txt)", loaded)
	}
}
