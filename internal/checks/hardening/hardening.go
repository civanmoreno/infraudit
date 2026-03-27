package hardening

import (
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&loginBanner{})
	check.Register(&coreDumps{})
	check.Register(&aslr{})
	check.Register(&dmesgRestrict{})
	check.Register(&ptraceScope{})
	check.Register(&procHardening{})
	check.Register(&swapEncrypted{})
	check.Register(&fsModules{})
	check.Register(&usbStorage{})
	check.Register(&wirelessModules{})
	check.Register(&firewireDMA{})
	check.Register(&bluetooth{})
}

func moduleBlacklisted(mod string) bool {
	// First check if the module is explicitly blacklisted in modprobe config
	out, err := check.RunCmd(check.DefaultCmdTimeout, "modprobe", "-n", "--show-depends", mod)
	if err != nil {
		// Distinguish between "module not found" (blacklisted/absent) and other errors
		errMsg := string(out) + err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "Module") {
			return true // Module genuinely doesn't exist
		}
		return false // Permission denied or other error — assume not blacklisted
	}
	return strings.Contains(string(out), "install /bin/true") ||
		strings.Contains(string(out), "install /bin/false") ||
		strings.Contains(string(out), "blacklist")
}

// HARD-001
type loginBanner struct{}

func (c *loginBanner) ID() string               { return "HARD-001" }
func (c *loginBanner) Name() string             { return "Login banner configured" }
func (c *loginBanner) Category() string         { return "hardening" }
func (c *loginBanner) Severity() check.Severity { return check.Low }
func (c *loginBanner) Description() string {
	return "Verify /etc/issue and /etc/issue.net have a warning banner"
}

func (c *loginBanner) Run() check.Result {
	var issues []string
	for _, path := range []string{"/etc/issue", "/etc/issue.net"} {
		data, err := os.ReadFile(check.P(path))
		if err != nil || len(strings.TrimSpace(string(data))) < 10 {
			issues = append(issues, path+" is empty or missing")
		}
	}
	if len(issues) > 0 {
		return check.Result{
			Status: check.Warn, Message: strings.Join(issues, "; "),
			Remediation: "Add a legal warning banner to /etc/issue and /etc/issue.net",
		}
	}
	return check.Result{Status: check.Pass, Message: "Login banners configured"}
}

// HARD-002
type coreDumps struct{}

func (c *coreDumps) ID() string               { return "HARD-002" }
func (c *coreDumps) Name() string             { return "Core dumps disabled" }
func (c *coreDumps) Category() string         { return "hardening" }
func (c *coreDumps) Severity() check.Severity { return check.Medium }
func (c *coreDumps) Description() string      { return "Verify core dumps are disabled" }

func (c *coreDumps) Run() check.Result {
	val := check.ReadSysctl("/proc/sys/kernel/core_pattern")
	// Check if core_pattern pipes to nothing or is disabled
	if strings.HasPrefix(val, "|") {
		// Piped to a handler (like apport) — may be acceptable
		return check.Result{Status: check.Pass, Message: "Core dumps piped to handler: " + val}
	}

	// Check limits
	data, err := os.ReadFile(check.P("/etc/security/limits.conf"))
	if err == nil && strings.Contains(string(data), "hard core 0") {
		return check.Result{Status: check.Pass, Message: "Core dumps disabled via limits.conf"}
	}

	return check.Result{
		Status: check.Warn, Message: "Core dumps may be enabled",
		Remediation: "Add '* hard core 0' to /etc/security/limits.conf and set fs.suid_dumpable=0",
	}
}

// HARD-003
type aslr struct{}

func (c *aslr) ID() string               { return "HARD-003" }
func (c *aslr) Name() string             { return "ASLR enabled" }
func (c *aslr) Category() string         { return "hardening" }
func (c *aslr) Severity() check.Severity { return check.High }
func (c *aslr) Description() string      { return "Verify ASLR is set to 2 (full randomization)" }

func (c *aslr) Run() check.Result {
	val := check.ReadSysctl("/proc/sys/kernel/randomize_va_space")
	if val == "2" {
		return check.Result{Status: check.Pass, Message: "ASLR is fully enabled (randomize_va_space=2)"}
	}
	return check.Result{
		Status: check.Fail, Message: "ASLR is not fully enabled (value=" + val + ")",
		Remediation: "Set: sysctl -w kernel.randomize_va_space=2",
	}
}

// HARD-004
type dmesgRestrict struct{}

func (c *dmesgRestrict) ID() string               { return "HARD-004" }
func (c *dmesgRestrict) Name() string             { return "dmesg restricted" }
func (c *dmesgRestrict) Category() string         { return "hardening" }
func (c *dmesgRestrict) Severity() check.Severity { return check.Medium }
func (c *dmesgRestrict) Description() string      { return "Verify kernel.dmesg_restrict = 1" }

func (c *dmesgRestrict) Run() check.Result {
	val := check.ReadSysctl("/proc/sys/kernel/dmesg_restrict")
	if val == "1" {
		return check.Result{Status: check.Pass, Message: "dmesg is restricted to privileged users"}
	}
	return check.Result{
		Status: check.Warn, Message: "dmesg is accessible to all users",
		Remediation: "Set: sysctl -w kernel.dmesg_restrict=1",
	}
}

// HARD-005
type ptraceScope struct{}

func (c *ptraceScope) ID() string               { return "HARD-005" }
func (c *ptraceScope) Name() string             { return "ptrace restricted" }
func (c *ptraceScope) Category() string         { return "hardening" }
func (c *ptraceScope) Severity() check.Severity { return check.Medium }
func (c *ptraceScope) Description() string      { return "Verify kernel.yama.ptrace_scope >= 1" }

func (c *ptraceScope) Run() check.Result {
	val := check.ReadSysctl("/proc/sys/kernel/yama/ptrace_scope")
	if val == "" {
		return check.Result{Status: check.Warn, Message: "Yama LSM not available"}
	}
	if val >= "1" {
		return check.Result{Status: check.Pass, Message: "ptrace restricted (scope=" + val + ")"}
	}
	return check.Result{
		Status: check.Warn, Message: "ptrace is unrestricted (scope=0)",
		Remediation: "Set: sysctl -w kernel.yama.ptrace_scope=1",
	}
}

// HARD-006
type procHardening struct{}

func (c *procHardening) ID() string               { return "HARD-006" }
func (c *procHardening) Name() string             { return "/proc hardened" }
func (c *procHardening) Category() string         { return "hardening" }
func (c *procHardening) Severity() check.Severity { return check.Medium }
func (c *procHardening) Description() string      { return "Verify /proc is mounted with hidepid" }

func (c *procHardening) Run() check.Result {
	mounts := check.ParseMounts()
	if mounts == nil {
		return check.Result{Status: check.Error, Message: "Cannot read /proc/mounts"}
	}
	for _, m := range mounts {
		if m.Mount == "/proc" {
			if strings.Contains(m.Options, "hidepid=") {
				return check.Result{Status: check.Pass, Message: "/proc mounted with hidepid"}
			}
		}
	}
	return check.Result{
		Status: check.Warn, Message: "/proc not mounted with hidepid",
		Remediation: "Mount /proc with hidepid=2: add 'proc /proc proc defaults,hidepid=2 0 0' to /etc/fstab",
	}
}

// HARD-007
type swapEncrypted struct{}

func (c *swapEncrypted) ID() string               { return "HARD-007" }
func (c *swapEncrypted) Name() string             { return "Swap encrypted or absent" }
func (c *swapEncrypted) Category() string         { return "hardening" }
func (c *swapEncrypted) Severity() check.Severity { return check.Low }
func (c *swapEncrypted) Description() string      { return "Verify swap is encrypted or not in use" }

func (c *swapEncrypted) Run() check.Result {
	data, err := os.ReadFile(check.P("/proc/swaps"))
	if err != nil {
		return check.Result{Status: check.Pass, Message: "No swap information available"}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) <= 1 {
		return check.Result{Status: check.Pass, Message: "No swap is active"}
	}

	// Check if swap devices are dm-crypt/LUKS
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			if strings.Contains(fields[0], "dm-") || strings.Contains(fields[0], "crypt") {
				return check.Result{Status: check.Pass, Message: "Swap appears to be encrypted"}
			}
		}
	}

	return check.Result{
		Status: check.Warn, Message: "Swap is active and may not be encrypted",
		Remediation: "Encrypt swap or disable if not needed",
	}
}

// HARD-008
type fsModules struct{}

func (c *fsModules) ID() string               { return "HARD-008" }
func (c *fsModules) Name() string             { return "Unused filesystem modules blacklisted" }
func (c *fsModules) Category() string         { return "hardening" }
func (c *fsModules) Severity() check.Severity { return check.Medium }
func (c *fsModules) Description() string {
	return "Verify cramfs, hfs, hfsplus, squashfs, udf, freevxfs, jffs2 are blacklisted"
}

func (c *fsModules) Run() check.Result {
	mods := []string{"cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "squashfs", "udf"}
	var loaded []string
	for _, m := range mods {
		if !moduleBlacklisted(m) {
			loaded = append(loaded, m)
		}
	}

	if len(loaded) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Filesystem modules not blacklisted: %s", strings.Join(loaded, ", ")),
			Remediation: "Blacklist: echo 'install <mod> /bin/true' >> /etc/modprobe.d/disable-fs.conf",
		}
	}
	return check.Result{Status: check.Pass, Message: "Unused filesystem modules are blacklisted"}
}

// HARD-009
type usbStorage struct{}

func (c *usbStorage) ID() string               { return "HARD-009" }
func (c *usbStorage) Name() string             { return "USB storage disabled if not needed" }
func (c *usbStorage) Category() string         { return "hardening" }
func (c *usbStorage) Severity() check.Severity { return check.Medium }
func (c *usbStorage) Description() string      { return "Verify usb-storage module is blacklisted" }

func (c *usbStorage) Run() check.Result {
	if moduleBlacklisted("usb-storage") {
		return check.Result{Status: check.Pass, Message: "usb-storage module is blacklisted"}
	}
	return check.Result{
		Status: check.Warn, Message: "usb-storage module is not blacklisted",
		Remediation: "Blacklist: echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb.conf",
	}
}

// HARD-010
type wirelessModules struct{}

func (c *wirelessModules) ID() string               { return "HARD-010" }
func (c *wirelessModules) Name() string             { return "Wireless modules disabled if not needed" }
func (c *wirelessModules) Category() string         { return "hardening" }
func (c *wirelessModules) Severity() check.Severity { return check.Low }
func (c *wirelessModules) Description() string {
	return "Verify wireless drivers are not loaded on servers"
}

func (c *wirelessModules) Run() check.Result {
	// Check if any wireless interfaces exist
	entries, _ := os.ReadDir(check.P("/sys/class/net"))
	for _, e := range entries {
		wirelessPath := check.P("/sys/class/net/" + e.Name() + "/wireless")
		if _, err := os.Stat(wirelessPath); err == nil {
			return check.Result{
				Status: check.Warn, Message: "Wireless interface found: " + e.Name(),
				Remediation: "Disable wireless if not needed on this server",
			}
		}
	}
	return check.Result{Status: check.Pass, Message: "No wireless interfaces detected"}
}

// HARD-011
type firewireDMA struct{}

func (c *firewireDMA) ID() string               { return "HARD-011" }
func (c *firewireDMA) Name() string             { return "Firewire/Thunderbolt DMA disabled" }
func (c *firewireDMA) Category() string         { return "hardening" }
func (c *firewireDMA) Severity() check.Severity { return check.Medium }
func (c *firewireDMA) Description() string {
	return "Verify firewire-core and thunderbolt modules are blacklisted"
}

func (c *firewireDMA) Run() check.Result {
	mods := []string{"firewire-core", "thunderbolt"}
	var notBlocked []string
	for _, m := range mods {
		if !moduleBlacklisted(m) {
			notBlocked = append(notBlocked, m)
		}
	}

	if len(notBlocked) > 0 {
		return check.Result{
			Status: check.Warn, Message: "DMA modules not blacklisted: " + strings.Join(notBlocked, ", "),
			Remediation: "Blacklist in /etc/modprobe.d/disable-dma.conf",
		}
	}
	return check.Result{Status: check.Pass, Message: "Firewire/Thunderbolt DMA modules blacklisted"}
}

// HARD-012
type bluetooth struct{}

func (c *bluetooth) ID() string               { return "HARD-012" }
func (c *bluetooth) Name() string             { return "Bluetooth disabled if not needed" }
func (c *bluetooth) Category() string         { return "hardening" }
func (c *bluetooth) Severity() check.Severity { return check.Low }
func (c *bluetooth) Description() string      { return "Verify bluetooth is disabled on servers" }

func (c *bluetooth) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "systemctl", "is-active", "bluetooth")
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		return check.Result{
			Status: check.Warn, Message: "Bluetooth service is active",
			Remediation: "Disable: 'systemctl disable --now bluetooth'",
		}
	}
	return check.Result{Status: check.Pass, Message: "Bluetooth is not active"}
}
