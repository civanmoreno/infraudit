package hardening

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/civanmoreno/infraudit/internal/check"
)

// setupFSRoot creates a temp directory, sets check.FSRoot to it,
// resets all caches, and returns a cleanup function.
func setupFSRoot(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	check.FSRoot = tmp
	check.ResetCache()
	t.Cleanup(func() {
		check.FSRoot = ""
		check.ResetCache()
	})
	return tmp
}

// writeFile creates a file under the temp root at the given absolute path.
func writeFile(t *testing.T, root, absPath, content string) {
	t.Helper()
	full := filepath.Join(root, absPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- HARD-003: ASLR ---

func TestASLR_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/randomize_va_space", "2")

	c := &aslr{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestASLR_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/randomize_va_space", "0")

	c := &aslr{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestASLR_Fail_Partial(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/randomize_va_space", "1")

	c := &aslr{}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL for value=1, got %s: %s", r.Status, r.Message)
	}
}

// --- HARD-004: dmesg restrict ---

func TestDmesgRestrict_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/dmesg_restrict", "1")

	c := &dmesgRestrict{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestDmesgRestrict_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/dmesg_restrict", "0")

	c := &dmesgRestrict{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- HARD-005: ptrace scope ---

func TestPtraceScope_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/yama/ptrace_scope", "1")

	c := &ptraceScope{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestPtraceScope_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/yama/ptrace_scope", "0")

	c := &ptraceScope{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestPtraceScope_Missing(t *testing.T) {
	_ = setupFSRoot(t)
	// Do not create the file — simulates Yama LSM not available

	c := &ptraceScope{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN for missing yama, got %s: %s", r.Status, r.Message)
	}
}

// --- HARD-002: core dumps ---

func TestCoreDumps_PassViaLimits(t *testing.T) {
	root := setupFSRoot(t)
	// core_pattern without pipe prefix so it falls through to limits check
	writeFile(t, root, "/proc/sys/kernel/core_pattern", "core")
	writeFile(t, root, "/etc/security/limits.conf", "* hard core 0\n")

	c := &coreDumps{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestCoreDumps_PassViaPipe(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/core_pattern", "|/usr/share/apport/apport")

	c := &coreDumps{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS for piped handler, got %s: %s", r.Status, r.Message)
	}
}

func TestCoreDumps_Warn(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/core_pattern", "core")
	writeFile(t, root, "/etc/security/limits.conf", "# no core limit\n")

	c := &coreDumps{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

// --- HARD-001: login banner ---

func TestLoginBanner_Pass(t *testing.T) {
	root := setupFSRoot(t)
	banner := "Authorized users only. All activity is monitored."
	writeFile(t, root, "/etc/issue", banner)
	writeFile(t, root, "/etc/issue.net", banner)

	c := &loginBanner{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginBanner_Warn_Empty(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/etc/issue", "")
	writeFile(t, root, "/etc/issue.net", "")

	c := &loginBanner{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginBanner_Warn_Missing(t *testing.T) {
	_ = setupFSRoot(t)
	// Files do not exist under the temp root

	c := &loginBanner{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN, got %s: %s", r.Status, r.Message)
	}
}

func TestLoginBanner_Warn_TooShort(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/etc/issue", "Hi")
	writeFile(t, root, "/etc/issue.net", "Hi")

	c := &loginBanner{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN for short banner, got %s: %s", r.Status, r.Message)
	}
}

// --- HARD-007: swap encrypted ---

func TestSwapEncrypted_NoSwap(t *testing.T) {
	root := setupFSRoot(t)
	// Only header line = no active swap
	writeFile(t, root, "/proc/swaps", "Filename\tType\tSize\tUsed\tPriority\n")

	c := &swapEncrypted{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestSwapEncrypted_Missing(t *testing.T) {
	_ = setupFSRoot(t)
	// /proc/swaps does not exist

	c := &swapEncrypted{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS when /proc/swaps missing, got %s: %s", r.Status, r.Message)
	}
}

func TestSwapEncrypted_Encrypted(t *testing.T) {
	root := setupFSRoot(t)
	content := "Filename\tType\tSize\tUsed\tPriority\n/dev/dm-0\tpartition\t4194300\t0\t-2\n"
	writeFile(t, root, "/proc/swaps", content)

	c := &swapEncrypted{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS for dm- swap, got %s: %s", r.Status, r.Message)
	}
}

func TestSwapEncrypted_Unencrypted(t *testing.T) {
	root := setupFSRoot(t)
	content := "Filename\tType\tSize\tUsed\tPriority\n/dev/sda2\tpartition\t4194300\t0\t-2\n"
	writeFile(t, root, "/proc/swaps", content)

	c := &swapEncrypted{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN for unencrypted swap, got %s: %s", r.Status, r.Message)
	}
}

// --- HARD-010: wireless modules ---

func TestWirelessModules_NoInterfaces(t *testing.T) {
	root := setupFSRoot(t)
	// Create /sys/class/net but with no wireless subdir
	netDir := filepath.Join(root, "sys/class/net/eth0")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}

	c := &wirelessModules{}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestWirelessModules_WirelessFound(t *testing.T) {
	root := setupFSRoot(t)
	// Create a wireless interface indicator
	wirelessDir := filepath.Join(root, "sys/class/net/wlan0/wireless")
	if err := os.MkdirAll(wirelessDir, 0o755); err != nil {
		t.Fatal(err)
	}

	c := &wirelessModules{}
	r := c.Run()
	if r.Status != check.Warn {
		t.Fatalf("expected WARN for wireless interface, got %s: %s", r.Status, r.Message)
	}
}

// --- Kernel advanced checks (kernel_advanced.go) ---

func TestKernelParam_KptrRestrict_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/kptr_restrict", "2")

	c := findKernelParam("HARD-020")
	if c == nil {
		t.Fatal("HARD-020 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_KptrRestrict_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/kptr_restrict", "0")

	c := findKernelParam("HARD-020")
	if c == nil {
		t.Fatal("HARD-020 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_PerfEventParanoid_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/perf_event_paranoid", "3")

	c := findKernelParam("HARD-021")
	if c == nil {
		t.Fatal("HARD-021 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_PerfEventParanoid_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/perf_event_paranoid", "1")

	c := findKernelParam("HARD-021")
	if c == nil {
		t.Fatal("HARD-021 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_SysRq_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/sysrq", "0")

	c := findKernelParam("HARD-022")
	if c == nil {
		t.Fatal("HARD-022 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_SysRq_Fail(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/sysrq", "1")

	c := findKernelParam("HARD-022")
	if c == nil {
		t.Fatal("HARD-022 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Fail {
		t.Fatalf("expected FAIL, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_SymlinkProtection_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/fs/protected_symlinks", "1")

	c := findKernelParam("HARD-025")
	if c == nil {
		t.Fatal("HARD-025 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_HardlinkProtection_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/fs/protected_hardlinks", "1")

	c := findKernelParam("HARD-026")
	if c == nil {
		t.Fatal("HARD-026 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_Missing(t *testing.T) {
	_ = setupFSRoot(t)
	// Do not create the file — should return Error

	c := findKernelParam("HARD-020")
	if c == nil {
		t.Fatal("HARD-020 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Error {
		t.Fatalf("expected ERROR for missing sysctl, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_BPFDisabled_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/unprivileged_bpf_disabled", "1")

	c := findKernelParam("HARD-017")
	if c == nil {
		t.Fatal("HARD-017 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_BPFJITHarden_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/net/core/bpf_jit_harden", "2")

	c := findKernelParam("HARD-018")
	if c == nil {
		t.Fatal("HARD-018 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_KexecDisabled_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/kexec_load_disabled", "1")

	c := findKernelParam("HARD-019")
	if c == nil {
		t.Fatal("HARD-019 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

func TestKernelParam_ModulesDisabled_Pass(t *testing.T) {
	root := setupFSRoot(t)
	writeFile(t, root, "/proc/sys/kernel/modules_disabled", "1")

	c := findKernelParam("HARD-024")
	if c == nil {
		t.Fatal("HARD-024 not found in kernelParams")
	}
	r := c.Run()
	if r.Status != check.Pass {
		t.Fatalf("expected PASS, got %s: %s", r.Status, r.Message)
	}
}

// --- Check metadata tests ---

func TestCheckMetadata(t *testing.T) {
	checks := []struct {
		c        check.Check
		id       string
		category string
	}{
		{&aslr{}, "HARD-003", "hardening"},
		{&dmesgRestrict{}, "HARD-004", "hardening"},
		{&ptraceScope{}, "HARD-005", "hardening"},
		{&loginBanner{}, "HARD-001", "hardening"},
		{&coreDumps{}, "HARD-002", "hardening"},
		{&swapEncrypted{}, "HARD-007", "hardening"},
		{&wirelessModules{}, "HARD-010", "hardening"},
	}
	for _, tc := range checks {
		if tc.c.ID() != tc.id {
			t.Errorf("%s: expected ID %s, got %s", tc.id, tc.id, tc.c.ID())
		}
		if tc.c.Category() != tc.category {
			t.Errorf("%s: expected category %s, got %s", tc.id, tc.category, tc.c.Category())
		}
		if tc.c.Name() == "" {
			t.Errorf("%s: Name() is empty", tc.id)
		}
		if tc.c.Description() == "" {
			t.Errorf("%s: Description() is empty", tc.id)
		}
	}
}

// --- Helpers ---

func findKernelParam(id string) *kernelParam {
	for _, p := range kernelParams {
		if p.id == id {
			return p
		}
	}
	return nil
}
