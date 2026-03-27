package logging

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
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// mkDir creates a directory under root with the given mode.
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

// --- Log Rotation (LOG-004) ---

func TestLogRotation_Configured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/logrotate.conf", "weekly\nrotate 4\n", 0644)

	c := &logRotation{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLogRotation_Missing(t *testing.T) {
	_ = setupFSRoot(t)
	// Do not create /etc/logrotate.conf

	c := &logRotation{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Log Permissions (LOG-005) ---

func TestLogPerms_Restrictive(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "var/log", 0750)
	writeFile(t, root, "var/log/syslog", "log data\n", 0640)
	writeFile(t, root, "var/log/auth.log", "auth data\n", 0640)
	writeFile(t, root, "var/log/kern.log", "kern data\n", 0640)

	c := &logPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLogPerms_WorldReadable(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "var/log", 0755)
	// Create more than 5 world-readable files to trigger WARN
	for _, name := range []string{"syslog", "auth.log", "kern.log", "daemon.log", "messages", "debug"} {
		writeFile(t, root, "var/log/"+name, "log data\n", 0666)
	}

	c := &logPerms{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestLogPerms_FewWorldReadable(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "var/log", 0755)
	// Only 3 world-readable files (<=5 threshold) -- still passes
	writeFile(t, root, "var/log/syslog", "log data\n", 0644)
	writeFile(t, root, "var/log/auth.log", "auth data\n", 0640)
	writeFile(t, root, "var/log/kern.log", "kern data\n", 0640)

	c := &logPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (<=5 world-readable), got %s: %s", r.Status, r.Message)
	}
}

// --- Journald Persistent (LOG-026) ---

func TestJournaldPersistent_Set(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\nStorage=persistent\n", 0644)

	c := &journaldPersistent{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestJournaldPersistent_NotSet(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\n#Storage=auto\n", 0644)

	c := &journaldPersistent{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestJournaldPersistent_Volatile(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\nStorage=volatile\n", 0644)

	c := &journaldPersistent{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestJournaldPersistent_MissingFile(t *testing.T) {
	_ = setupFSRoot(t)
	// No journald.conf -- journaldConfValue returns ""

	c := &journaldPersistent{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Journald Compress (LOG-025) ---

func TestJournaldCompress_Yes(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\nCompress=yes\n", 0644)

	c := &journaldCompress{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestJournaldCompress_No(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\nCompress=no\n", 0644)

	c := &journaldCompress{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestJournaldCompress_Default(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\n#Compress=yes\n", 0644)

	c := &journaldCompress{}
	r := c.Run()
	// Default (empty value) is treated as yes -> PASS
	if r.Status != check.Pass {
		t.Errorf("expected PASS (default), got %s: %s", r.Status, r.Message)
	}
}

// --- Audit Log Size (LOG-010) ---

func TestAuditLogSize_Configured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/audit/auditd.conf", "max_log_file = 8\nmax_log_file_action = keep_logs\n", 0640)

	c := &auditLogSize{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestAuditLogSize_NotConfigured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/audit/auditd.conf", "# empty config\n", 0640)

	c := &auditLogSize{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestAuditLogSize_MissingFile(t *testing.T) {
	_ = setupFSRoot(t)
	// No auditd.conf -- auditdConfValue returns ""

	c := &auditLogSize{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Audit Log Full Action (LOG-011) ---

func TestAuditLogFull_Configured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/audit/auditd.conf", "space_left_action = email\n", 0640)

	c := &auditLogFull{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestAuditLogFull_Ignore(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/audit/auditd.conf", "space_left_action = ignore\n", 0640)

	c := &auditLogFull{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- Audit Log Retain (LOG-012) ---

func TestAuditLogRetain_KeepLogs(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/audit/auditd.conf", "max_log_file_action = keep_logs\n", 0640)

	c := &auditLogRetain{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestAuditLogRetain_Rotate(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/audit/auditd.conf", "max_log_file_action = rotate\n", 0640)

	c := &auditLogRetain{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Journald Forward (LOG-028) ---

func TestJournaldForward_Enabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\nForwardToSyslog=yes\n", 0644)

	c := &journaldForward{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestJournaldForward_Disabled(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/systemd/journald.conf", "[Journal]\nForwardToSyslog=no\n", 0644)

	c := &journaldForward{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- /var/log directory permissions (LOG-034) ---

func TestLogDirPerms_Restrictive(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "var/log", 0750)

	c := &logPermissions{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLogDirPerms_TooOpen(t *testing.T) {
	root := setupFSRoot(t)
	mkDir(t, root, "var/log", 0755)

	c := &logPermissions{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Rsyslog Remote Logging (LOG-029) ---

func TestRsyslogRemote_Configured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/rsyslog.conf", "*.* @@loghost.example.com:514\n", 0644)

	c := &rsyslogRemote{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRsyslogRemote_NotConfigured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/rsyslog.conf", "# no remote logging\n", 0644)

	c := &rsyslogRemote{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Rsyslog No Receive (LOG-030) ---

func TestRsyslogNoReceive_Clean(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/rsyslog.conf", "# standard config\n*.* /var/log/syslog\n", 0644)

	c := &rsyslogNoReceive{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRsyslogNoReceive_AcceptingRemote(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/rsyslog.conf", "module(load=\"imtcp\")\ninput(type=\"imtcp\" port=\"514\")\n", 0644)

	c := &rsyslogNoReceive{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- Rsyslog File Permissions (LOG-027) ---

func TestRsyslogPerms_Configured(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/rsyslog.conf", "$FileCreateMode 0640\n", 0644)

	c := &rsyslogPerms{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestRsyslogPerms_TooPermissive(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/rsyslog.conf", "$FileCreateMode 0644\n", 0644)

	c := &rsyslogPerms{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestRsyslogPerms_NotSet(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/rsyslog.conf", "# no FileCreateMode\n", 0644)

	c := &rsyslogPerms{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}
