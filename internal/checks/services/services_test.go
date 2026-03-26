package services

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
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// --- SSH Ciphers and Timeouts (SVC-002 / sshHardening) ---

func TestSSHHardening_StrongCiphers_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config",
		"Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com\n"+
			"MACs hmac-sha2-512-etm@openssh.com\n"+
			"ClientAliveInterval 300\n"+
			"ClientAliveCountMax 3\n",
	)

	c := &sshHardening{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHHardening_WeakCipher_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config",
		"Ciphers 3des-cbc,aes128-ctr\n"+
			"ClientAliveInterval 300\n"+
			"ClientAliveCountMax 3\n",
	)

	c := &sshHardening{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHHardening_TimeoutSet_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config",
		"ClientAliveInterval 300\n"+
			"ClientAliveCountMax 3\n",
	)

	c := &sshHardening{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHHardening_TimeoutNotSet_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config",
		"# No timeout settings\nPermitRootLogin no\n",
	)

	c := &sshHardening{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHHardening_Protocol2_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config",
		"Protocol 2\n"+
			"ClientAliveInterval 300\n"+
			"ClientAliveCountMax 3\n",
	)

	c := &sshHardening{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- SSH PermitEmptyPasswords (SVC-028) ---

func TestSSHPermitEmptyPasswords_No_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PermitEmptyPasswords no\n")

	c := &sshSetting{
		id: "SVC-028", directive: "PermitEmptyPasswords",
		expected: "no", compare: "eq",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHPermitEmptyPasswords_Yes_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PermitEmptyPasswords yes\n")

	c := &sshSetting{
		id: "SVC-028", directive: "PermitEmptyPasswords",
		expected: "no", compare: "eq",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- SSH MaxAuthTries (SVC-029) ---

func TestSSHMaxAuthTries_4_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "MaxAuthTries 4\n")

	c := &sshSetting{
		id: "SVC-029", directive: "MaxAuthTries",
		expected: "4", compare: "le",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHMaxAuthTries_10_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "MaxAuthTries 10\n")

	c := &sshSetting{
		id: "SVC-029", directive: "MaxAuthTries",
		expected: "4", compare: "le",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// --- SSH LoginGraceTime (SVC-032) ---

func TestSSHLoginGraceTime_60_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "LoginGraceTime 60\n")

	c := &sshSetting{
		id: "SVC-032", directive: "LoginGraceTime",
		expected: "60", compare: "le",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHLoginGraceTime_120_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "LoginGraceTime 120\n")

	c := &sshSetting{
		id: "SVC-032", directive: "LoginGraceTime",
		expected: "60", compare: "le",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHLoginGraceTime_NotSet_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "# empty config\n")

	c := &sshSetting{
		id: "SVC-032", directive: "LoginGraceTime",
		expected: "60", compare: "le", remedy: "Set LoginGraceTime 60",
	}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- MTA Local Only (SVC-009) ---

func TestMTALocalOnly_LoopbackOnly_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/postfix/main.cf", "inet_interfaces = loopback-only\n")

	c := &mtaLocalOnly{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestMTALocalOnly_Localhost_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/postfix/main.cf", "inet_interfaces = localhost\n")

	c := &mtaLocalOnly{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestMTALocalOnly_All_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/postfix/main.cf", "inet_interfaces = all\n")

	c := &mtaLocalOnly{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}
