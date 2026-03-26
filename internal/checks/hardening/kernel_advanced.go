package hardening

import (
	"fmt"

	"github.com/civanmoreno/infraudit/internal/check"
)

type kernelParam struct {
	id       string
	name     string
	desc     string
	severity check.Severity
	path     string
	expected string
	remedy   string
}

func (c *kernelParam) ID() string               { return c.id }
func (c *kernelParam) Name() string             { return c.name }
func (c *kernelParam) Category() string         { return "hardening" }
func (c *kernelParam) Severity() check.Severity { return c.severity }
func (c *kernelParam) Description() string      { return c.desc }

func (c *kernelParam) Run() check.Result {
	val := check.ReadSysctl(c.path)
	if val == "" {
		return check.Result{Status: check.Error, Message: fmt.Sprintf("Cannot read %s", c.path), Remediation: "This sysctl may not be available on your kernel version, or run with sudo"}
	}
	if val != c.expected {
		return check.Result{
			Status: check.Fail, Message: fmt.Sprintf("%s = %s (expected %s)", c.path, val, c.expected),
			Remediation: c.remedy,
		}
	}
	return check.Result{Status: check.Pass, Message: fmt.Sprintf("%s = %s", c.path, val)}
}

func init() {
	for _, p := range kernelParams {
		check.Register(p)
	}
}

var kernelParams = []*kernelParam{
	{id: "HARD-017", name: "Unprivileged BPF disabled", desc: "Ensure unprivileged BPF is disabled", severity: check.Medium,
		path: "/proc/sys/kernel/unprivileged_bpf_disabled", expected: "1", remedy: "sysctl -w kernel.unprivileged_bpf_disabled=1"},
	{id: "HARD-018", name: "BPF JIT hardening enabled", desc: "Ensure BPF JIT compiler is hardened", severity: check.Medium,
		path: "/proc/sys/net/core/bpf_jit_harden", expected: "2", remedy: "sysctl -w net.core.bpf_jit_harden=2"},
	{id: "HARD-019", name: "Kexec load disabled", desc: "Ensure kexec_load is restricted", severity: check.Medium,
		path: "/proc/sys/kernel/kexec_load_disabled", expected: "1", remedy: "sysctl -w kernel.kexec_load_disabled=1"},
	{id: "HARD-020", name: "Kernel pointer hiding enabled", desc: "Ensure kernel pointers are hidden from unprivileged users", severity: check.Medium,
		path: "/proc/sys/kernel/kptr_restrict", expected: "2", remedy: "sysctl -w kernel.kptr_restrict=2"},
	{id: "HARD-021", name: "Performance events restricted", desc: "Ensure perf_event_paranoid is set to 3", severity: check.Low,
		path: "/proc/sys/kernel/perf_event_paranoid", expected: "3", remedy: "sysctl -w kernel.perf_event_paranoid=3"},
	{id: "HARD-022", name: "SysRq key restricted", desc: "Ensure SysRq key is disabled or restricted", severity: check.Low,
		path: "/proc/sys/kernel/sysrq", expected: "0", remedy: "sysctl -w kernel.sysrq=0"},
	{id: "HARD-023", name: "User namespaces restricted", desc: "Ensure unprivileged user namespaces are restricted", severity: check.Medium,
		path: "/proc/sys/kernel/unprivileged_userns_clone", expected: "0", remedy: "sysctl -w kernel.unprivileged_userns_clone=0"},
	{id: "HARD-024", name: "Kernel module loading restricted", desc: "Ensure kernel module loading is restricted", severity: check.High,
		path: "/proc/sys/kernel/modules_disabled", expected: "1", remedy: "sysctl -w kernel.modules_disabled=1 (WARNING: cannot be reversed without reboot)"},
	{id: "HARD-025", name: "Symlink protection enabled", desc: "Ensure symlinks are protected", severity: check.Medium,
		path: "/proc/sys/fs/protected_symlinks", expected: "1", remedy: "sysctl -w fs.protected_symlinks=1"},
	{id: "HARD-026", name: "Hardlink protection enabled", desc: "Ensure hardlinks are protected", severity: check.Medium,
		path: "/proc/sys/fs/protected_hardlinks", expected: "1", remedy: "sysctl -w fs.protected_hardlinks=1"},
}
