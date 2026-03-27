package services

import (
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

// =============================================================
// XDMCP Disabled (SVC-050) — services_advanced.go
// =============================================================

func TestXDMCP_NoGDM(t *testing.T) {
	_ = setupFSRoot(t) // no gdm3/custom.conf
	c := &xdmcpDisabled{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no GDM), got %s: %s", r.Status, r.Message)
	}
}

func TestXDMCP_Enabled_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/gdm3/custom.conf",
		"[xdmcp]\nEnable=true\n")

	c := &xdmcpDisabled{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL (XDMCP enabled), got %s: %s", r.Status, r.Message)
	}
}

func TestXDMCP_Disabled_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/gdm3/custom.conf",
		"[xdmcp]\nEnable=false\n")

	c := &xdmcpDisabled{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (XDMCP disabled), got %s: %s", r.Status, r.Message)
	}
}

func TestXDMCP_EmptyConfig_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/gdm3/custom.conf",
		"[daemon]\nAutomaticLoginEnable=false\n")

	c := &xdmcpDisabled{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no XDMCP section), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// MTA Open Relay (SVC-010) — mta.go
// =============================================================

func TestMTAOpenRelay_NoPostfix(t *testing.T) {
	_ = setupFSRoot(t)
	c := &mtaOpenRelay{}
	r := c.Run()
	// Postfix not running in test env
	if r.Status != check.Pass {
		t.Errorf("expected PASS (no postfix), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// MTA Root Alias (SVC-011) — mta.go
// =============================================================

func TestMTARootAlias_Present_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/aliases",
		"# mail aliases\npostmaster: root\nroot: admin@example.com\n")

	c := &mtaRootAlias{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestMTARootAlias_Missing_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/aliases",
		"# mail aliases\npostmaster: root\n")

	c := &mtaRootAlias{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (no root alias), got %s: %s", r.Status, r.Message)
	}
}

func TestMTARootAlias_NoFile_Warn(t *testing.T) {
	_ = setupFSRoot(t)

	c := &mtaRootAlias{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (no aliases file), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// Sudo pty and log (SVC-040, SVC-041) — ssh_settings.go
// =============================================================

func TestSudoPty_Configured_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers",
		"Defaults use_pty\nroot ALL=(ALL) ALL\n")

	c := &sudoPty{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSudoPty_NotConfigured_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers",
		"root ALL=(ALL) ALL\n")

	c := &sudoPty{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestSudoLog_Configured_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers",
		"Defaults logfile=/var/log/sudo.log\nroot ALL=(ALL) ALL\n")

	c := &sudoLog{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSudoLog_NotConfigured_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers",
		"root ALL=(ALL) ALL\n")

	c := &sudoLog{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestSudoPty_DropIn_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/sudoers", "root ALL=(ALL) ALL\n")
	writeFile(t, root, "etc/sudoers.d/hardening",
		"Defaults use_pty\n")

	c := &sudoPty{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (drop-in), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// SSH Hardening edge cases (SVC-002) — ssh_hardening.go
// =============================================================

func TestSSHHardening_NoConfig(t *testing.T) {
	_ = setupFSRoot(t) // no sshd_config

	c := &sshHardening{}
	r := c.Run()
	// parseSSHConfig returns nil, so issues = [ClientAliveInterval not set, ClientAliveCountMax not set]
	if r.Status != check.Warn {
		t.Errorf("expected WARN (no config), got %s: %s", r.Status, r.Message)
	}
}

func TestSSHHardening_WeakMAC_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config",
		"MACs hmac-md5,hmac-sha2-256\n"+
			"ClientAliveInterval 300\n"+
			"ClientAliveCountMax 3\n")

	c := &sshHardening{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Errorf("expected WARN (weak MAC), got %s: %s", r.Status, r.Message)
	}
}

// =============================================================
// SSH Settings edge cases — ssh_settings.go
// =============================================================

func TestSSHSetting_IgnoreRhosts_Yes_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "IgnoreRhosts yes\n")

	c := &sshSetting{
		id: "SVC-030", directive: "IgnoreRhosts",
		expected: "yes", compare: "eq",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHSetting_IgnoreRhosts_No_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "IgnoreRhosts no\n")

	c := &sshSetting{
		id: "SVC-030", directive: "IgnoreRhosts",
		expected: "yes", compare: "eq",
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Errorf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestSSHSetting_NonemptyCompare_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "MaxStartups 10:30:60\n")

	c := &sshSetting{
		id: "SVC-033", directive: "MaxStartups",
		expected: "", compare: "nonempty",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (nonempty), got %s: %s", r.Status, r.Message)
	}
}

func TestSSHSetting_NeCompare_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "PermitRootLogin no\n")

	c := &sshSetting{
		id: "TEST-NE", directive: "PermitRootLogin",
		expected: "yes", compare: "ne",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (ne comparison), got %s: %s", r.Status, r.Message)
	}
}

func TestSSHSetting_DropIn_Override(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "etc/ssh/sshd_config", "# base config\n")
	writeFile(t, root, "etc/ssh/sshd_config.d/50-hardening.conf",
		"PermitEmptyPasswords no\n")

	c := &sshSetting{
		id: "SVC-028", directive: "PermitEmptyPasswords",
		expected: "no", compare: "eq",
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Errorf("expected PASS (drop-in), got %s: %s", r.Status, r.Message)
	}
}
