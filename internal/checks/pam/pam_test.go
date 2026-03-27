package pam

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

// setupFSRoot creates a temp directory, sets check.FSRoot, and returns a
// cleanup function that resets FSRoot and the caches.
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

// writeFile creates a file under the temp FSRoot with the given contents.
func writeFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	abs := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

// ---------- PAM-001: pwquality ----------

func TestPwquality_Pass(t *testing.T) {
	root := setupFSRoot(t)

	// pam_pwquality must be enabled in a PAM password config
	writeFile(t, root, "etc/pam.d/common-password",
		"password requisite pam_pwquality.so retry=3\n")

	// Good pwquality.conf settings
	writeFile(t, root, "etc/security/pwquality.conf",
		"minlen = 14\nminclass = 4\n")

	c := &pwquality{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPwquality_WarnWeakSettings(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/pam.d/common-password",
		"password requisite pam_pwquality.so retry=3\n")

	// Missing minlen (defaults to 0 which is < 14)
	writeFile(t, root, "etc/security/pwquality.conf",
		"minclass = 4\n")

	c := &pwquality{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestPwquality_FailNotEnabled(t *testing.T) {
	root := setupFSRoot(t)

	// PAM config exists but does not mention pam_pwquality
	writeFile(t, root, "etc/pam.d/common-password",
		"password required pam_unix.so\n")

	c := &pwquality{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-002: pwhistory ----------

func TestPwhistory_Pass(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/pam.d/common-password",
		"password required pam_pwhistory.so remember=5 use_authtok\n")

	c := &pwhistory{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPwhistory_Fail(t *testing.T) {
	root := setupFSRoot(t)

	// No remember= anywhere
	writeFile(t, root, "etc/pam.d/common-password",
		"password required pam_unix.so\n")

	c := &pwhistory{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestPwhistory_WarnLowRemember(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/pam.d/common-password",
		"password required pam_pwhistory.so remember=2 use_authtok\n")

	c := &pwhistory{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-003: faillock ----------

func TestFaillock_Pass(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/security/faillock.conf",
		"deny = 5\nunlock_time = 900\n")

	c := &faillock{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestFaillock_WarnDenyTooHigh(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/security/faillock.conf",
		"deny = 15\nunlock_time = 900\n")

	c := &faillock{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestFaillock_FailNotConfigured(t *testing.T) {
	root := setupFSRoot(t)

	// No faillock.conf, no pam_faillock in any PAM config
	writeFile(t, root, "etc/pam.d/common-auth",
		"auth required pam_unix.so\n")

	c := &faillock{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-005: passwordExpiry ----------

func TestPasswordExpiry_Pass(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs",
		"PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n")

	c := &passwordExpiry{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPasswordExpiry_WarnMaxDaysTooHigh(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs",
		"PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\n")

	c := &passwordExpiry{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-006: pamNullok ----------

func TestPamNullok_Pass(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/pam.d/common-auth",
		"auth required pam_unix.so\n")

	c := &pamNullok{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPamNullok_Fail(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/pam.d/common-auth",
		"auth required pam_unix.so nullok\n")

	c := &pamNullok{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestPamNullok_PassNoFiles(t *testing.T) {
	_ = setupFSRoot(t)

	// No PAM auth files exist at all -- should pass (all reads fail, no nullok found)
	c := &pamNullok{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS when no files exist, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-009: loginDefsUID ----------

func TestLoginDefsUID_Pass(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "UID_MIN 1000\n")

	c := &loginDefsUID{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginDefsUID_Warn(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "UID_MIN 500\n")

	c := &loginDefsUID{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginDefsUID_WarnMissing(t *testing.T) {
	root := setupFSRoot(t)

	// login.defs exists but has no UID_MIN
	writeFile(t, root, "etc/login.defs", "# nothing relevant\n")

	c := &loginDefsUID{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-011: loginDefsUmask ----------

func TestLoginDefsUmask_Pass(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "UMASK 027\n")

	c := &loginDefsUmask{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginDefsUmask_PassMoreRestrictive(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "UMASK 077\n")

	c := &loginDefsUmask{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginDefsUmask_Fail(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "UMASK 022\n")

	c := &loginDefsUmask{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-012: loginDefsEncrypt ----------

func TestLoginDefsEncrypt_PassSHA512(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "ENCRYPT_METHOD SHA512\n")

	c := &loginDefsEncrypt{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginDefsEncrypt_PassYescrypt(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "ENCRYPT_METHOD yescrypt\n")

	c := &loginDefsEncrypt{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginDefsEncrypt_FailMD5(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "ENCRYPT_METHOD MD5\n")

	c := &loginDefsEncrypt{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginDefsEncrypt_WarnMissing(t *testing.T) {
	root := setupFSRoot(t)

	writeFile(t, root, "etc/login.defs", "# no encrypt method\n")

	c := &loginDefsEncrypt{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// ---------- PAM-004: pamOrder ----------

func TestPamOrder_PassCorrectOrder(t *testing.T) {
	root := setupFSRoot(t)

	// faillock before unix -- correct order
	writeFile(t, root, "etc/pam.d/common-auth",
		"auth required pam_faillock.so preauth\nauth required pam_unix.so\nauth required pam_faillock.so authfail\n")

	c := &pamOrder{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPamOrder_FailWrongOrder(t *testing.T) {
	root := setupFSRoot(t)

	// unix before faillock -- wrong order
	writeFile(t, root, "etc/pam.d/common-auth",
		"auth required pam_unix.so\nauth required pam_faillock.so preauth\n")

	c := &pamOrder{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestPamOrder_PassNoFaillock(t *testing.T) {
	root := setupFSRoot(t)

	// No faillock at all -- passes (faillock not in use)
	writeFile(t, root, "etc/pam.d/common-auth",
		"auth required pam_unix.so\n")

	c := &pamOrder{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}
