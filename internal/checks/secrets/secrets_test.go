package secrets

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
	if err := os.MkdirAll(path, 0755); err != nil {
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

// --- envSecrets tests ---

func TestEnvSecrets_Fail(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "environment"),
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n", 0644)

	c := &envSecrets{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestEnvSecrets_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "environment"),
		"PATH=/usr/local/bin:/usr/bin\nLANG=en_US.UTF-8\n", 0644)

	c := &envSecrets{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestEnvSecrets_CommentsIgnored(t *testing.T) {
	tmp := setupTmpRoot(t)
	writeFile(t, filepath.Join(tmp, "etc", "environment"),
		"# AWS_SECRET_ACCESS_KEY=test\n", 0644)

	c := &envSecrets{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (comment line), got %s: %s", r.Status, r.Message)
	}
}

// --- historySecrets tests ---

func TestHistorySecrets_Warn(t *testing.T) {
	tmp := setupTmpRoot(t)
	homeDir := filepath.Join(tmp, "home", "testuser")
	writeFile(t, filepath.Join(homeDir, ".bash_history"),
		"ls -la\nmysql -u root -p password\nexit\n", 0600)

	c := &historySecrets{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestHistorySecrets_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	homeDir := filepath.Join(tmp, "home", "testuser")
	writeFile(t, filepath.Join(homeDir, ".bash_history"),
		"ls -la\ncd /tmp\nexit\n", 0600)

	c := &historySecrets{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- credFilePerms tests ---

func TestCredFilePerms_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	homeDir := filepath.Join(tmp, "home", "testuser")
	pgpass := filepath.Join(homeDir, ".pgpass")
	mycnf := filepath.Join(homeDir, ".my.cnf")
	writeFile(t, pgpass, "localhost:5432:*:user:pass\n", 0600)
	writeFile(t, mycnf, "[client]\npassword=secret\n", 0600)

	c := &credFilePerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestCredFilePerms_Warn(t *testing.T) {
	tmp := setupTmpRoot(t)
	homeDir := filepath.Join(tmp, "home", "testuser")
	pgpass := filepath.Join(homeDir, ".pgpass")
	writeFile(t, pgpass, "localhost:5432:*:user:pass\n", 0644)

	c := &credFilePerms{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- worldReadableCreds tests ---

func TestWorldReadableCreds_Fail(t *testing.T) {
	tmp := setupTmpRoot(t)
	shadow := filepath.Join(tmp, "etc", "shadow")
	writeFile(t, shadow, "root:$6$hash:19000:0:99999:7:::\n", 0644)

	c := &worldReadableCreds{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestWorldReadableCreds_Pass(t *testing.T) {
	tmp := setupTmpRoot(t)
	shadow := filepath.Join(tmp, "etc", "shadow")
	writeFile(t, shadow, "root:$6$hash:19000:0:99999:7:::\n", 0640)

	c := &worldReadableCreds{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestWorldReadableCreds_PassMissing(t *testing.T) {
	_ = setupTmpRoot(t)
	// No files created -- all stat calls will fail, should pass.
	c := &worldReadableCreds{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (missing files), got %s: %s", r.Status, r.Message)
	}
}
