package boot

import (
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&grubPassword{})
	check.Register(&grubPerms{})
	check.Register(&secureBoot{})
	check.Register(&singleUserAuth{})
	check.Register(&macInstalled{})
	check.Register(&macEnforcing{})
	check.Register(&unconfinedProcs{})
	check.Register(&macDenials{})
}

// BOOT-001
type grubPassword struct{}

func (c *grubPassword) ID() string             { return "BOOT-001" }
func (c *grubPassword) Name() string           { return "GRUB bootloader password set" }
func (c *grubPassword) Category() string       { return "boot" }
func (c *grubPassword) Severity() check.Severity { return check.High }
func (c *grubPassword) Description() string    { return "Verify GRUB has a password configured" }

func (c *grubPassword) Run() check.Result {
	paths := []string{
		"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg",
		"/boot/efi/EFI/ubuntu/grub.cfg",
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "password_pbkdf2") || strings.Contains(string(data), "set superusers") {
			return check.Result{Status: check.Pass, Message: "GRUB password is configured"}
		}
	}

	// Check user.cfg
	for _, p := range []string{"/boot/grub/user.cfg", "/boot/grub2/user.cfg"} {
		if _, err := os.Stat(p); err == nil {
			return check.Result{Status: check.Pass, Message: "GRUB user.cfg found (password likely set)"}
		}
	}

	return check.Result{
		Status: check.Warn, Message: "GRUB password not detected",
		Remediation: "Set GRUB password: grub-mkpasswd-pbkdf2 and add to /etc/grub.d/40_custom",
	}
}

// BOOT-002
type grubPerms struct{}

func (c *grubPerms) ID() string             { return "BOOT-002" }
func (c *grubPerms) Name() string           { return "Bootloader config permissions" }
func (c *grubPerms) Category() string       { return "boot" }
func (c *grubPerms) Severity() check.Severity { return check.High }
func (c *grubPerms) Description() string    { return "Verify grub.cfg is 0600 owned by root" }

func (c *grubPerms) Run() check.Result {
	paths := []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm > 0600 {
			return check.Result{
				Status:      check.Fail,
				Message:     p + " has permissions " + perm.String(),
				Remediation: "Fix: chmod 600 " + p,
			}
		}
		return check.Result{Status: check.Pass, Message: p + " permissions are correct"}
	}
	return check.Result{Status: check.Warn, Message: "GRUB config not found"}
}

// BOOT-003
type secureBoot struct{}

func (c *secureBoot) ID() string             { return "BOOT-003" }
func (c *secureBoot) Name() string           { return "UEFI Secure Boot enabled" }
func (c *secureBoot) Category() string       { return "boot" }
func (c *secureBoot) Severity() check.Severity { return check.Medium }
func (c *secureBoot) Description() string    { return "Check if Secure Boot is enabled" }

func (c *secureBoot) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "mokutil", "--sb-state")
	if err == nil {
		if strings.Contains(string(out), "SecureBoot enabled") {
			return check.Result{Status: check.Pass, Message: "Secure Boot is enabled"}
		}
		return check.Result{
			Status: check.Warn, Message: "Secure Boot is disabled",
			Remediation: "Enable Secure Boot in UEFI/BIOS settings",
		}
	}

	// Check via EFI variable
	data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err == nil && len(data) >= 5 && data[4] == 1 {
		return check.Result{Status: check.Pass, Message: "Secure Boot is enabled"}
	}

	return check.Result{Status: check.Warn, Message: "Could not determine Secure Boot status"}
}

// BOOT-004
type singleUserAuth struct{}

func (c *singleUserAuth) ID() string             { return "BOOT-004" }
func (c *singleUserAuth) Name() string           { return "Single-user mode requires authentication" }
func (c *singleUserAuth) Category() string       { return "boot" }
func (c *singleUserAuth) Severity() check.Severity { return check.High }
func (c *singleUserAuth) Description() string    { return "Verify rescue/emergency mode requires root password" }

func (c *singleUserAuth) Run() check.Result {
	entries, err := check.ParseShadow()
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/shadow: " + err.Error()}
	}
	for _, e := range entries {
		if e.User == "root" {
			if e.Hash == "" || e.Hash == "*" || e.Hash == "!" || e.Hash == "!!" {
				return check.Result{
					Status:      check.Fail,
					Message:     "root account has no password (single-user mode unprotected)",
					Remediation: "Set root password: passwd root",
				}
			}
			return check.Result{Status: check.Pass, Message: "root has a password set"}
		}
	}
	return check.Result{Status: check.Error, Message: "Could not find root entry in /etc/shadow"}
}

// BOOT-005
type macInstalled struct{}

func (c *macInstalled) ID() string             { return "BOOT-005" }
func (c *macInstalled) Name() string           { return "SELinux or AppArmor installed and enabled" }
func (c *macInstalled) Category() string       { return "boot" }
func (c *macInstalled) Severity() check.Severity { return check.High }
func (c *macInstalled) Description() string    { return "Verify a mandatory access control system is active" }

func (c *macInstalled) Run() check.Result {
	// Check AppArmor
	out, err := check.RunCmd(check.DefaultCmdTimeout, "aa-status", "--enabled")
	if err == nil && strings.Contains(string(out), "Yes") {
		return check.Result{Status: check.Pass, Message: "AppArmor is enabled"}
	}
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		return check.Result{Status: check.Pass, Message: "AppArmor is available"}
	}

	// Check SELinux
	out, err = check.RunCmd(check.DefaultCmdTimeout, "getenforce")
	if err == nil {
		mode := strings.TrimSpace(string(out))
		if mode == "Enforcing" || mode == "Permissive" {
			return check.Result{Status: check.Pass, Message: "SELinux is " + mode}
		}
	}

	return check.Result{
		Status: check.Fail, Message: "No MAC system (SELinux/AppArmor) detected",
		Remediation: "Install AppArmor or SELinux and enable it",
	}
}

// BOOT-006
type macEnforcing struct{}

func (c *macEnforcing) ID() string             { return "BOOT-006" }
func (c *macEnforcing) Name() string           { return "MAC in enforcing mode" }
func (c *macEnforcing) Category() string       { return "boot" }
func (c *macEnforcing) Severity() check.Severity { return check.High }
func (c *macEnforcing) Description() string    { return "Verify SELinux is Enforcing or AppArmor profiles are in enforce mode" }

func (c *macEnforcing) Run() check.Result {
	// AppArmor
	out, err := check.RunCmd(check.DefaultCmdTimeout, "aa-status")
	if err == nil {
		output := string(out)
		if strings.Contains(output, "enforce") {
			return check.Result{Status: check.Pass, Message: "AppArmor has profiles in enforce mode"}
		}
	}

	// SELinux
	out, err = check.RunCmd(check.DefaultCmdTimeout, "getenforce")
	if err == nil {
		mode := strings.TrimSpace(string(out))
		if mode == "Enforcing" {
			return check.Result{Status: check.Pass, Message: "SELinux is in Enforcing mode"}
		}
		if mode == "Permissive" {
			return check.Result{
				Status: check.Warn, Message: "SELinux is in Permissive mode",
				Remediation: "Set SELinux to Enforcing in /etc/selinux/config",
			}
		}
	}

	return check.Result{Status: check.Warn, Message: "Could not determine MAC enforcement status"}
}

// BOOT-007
type unconfinedProcs struct{}

func (c *unconfinedProcs) ID() string             { return "BOOT-007" }
func (c *unconfinedProcs) Name() string           { return "No unconfined processes" }
func (c *unconfinedProcs) Category() string       { return "boot" }
func (c *unconfinedProcs) Severity() check.Severity { return check.Medium }
func (c *unconfinedProcs) Description() string    { return "Check for processes without MAC confinement" }

func (c *unconfinedProcs) Run() check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, "aa-unconfined")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		count := 0
		for _, l := range lines {
			if strings.Contains(l, "not confined") {
				count++
			}
		}
		if count > 0 {
			return check.Result{
				Status:  check.Warn,
				Message: fmt.Sprintf("%d", count) + " unconfined processes found",
			}
		}
		return check.Result{Status: check.Pass, Message: "No unconfined processes"}
	}
	return check.Result{Status: check.Pass, Message: "aa-unconfined not available (skipped)"}
}

// BOOT-008
type macDenials struct{}

func (c *macDenials) ID() string             { return "BOOT-008" }
func (c *macDenials) Name() string           { return "No MAC denials in logs" }
func (c *macDenials) Category() string       { return "boot" }
func (c *macDenials) Severity() check.Severity { return check.Low }
func (c *macDenials) Description() string    { return "Check for recent SELinux/AppArmor denials" }

func (c *macDenials) Run() check.Result {
	// Check AppArmor denials in dmesg
	out, _ := check.RunCmd(check.DefaultCmdTimeout, "dmesg")
	output := string(out)
	denials := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "apparmor=\"DENIED\"") || strings.Contains(line, "avc:  denied") {
			denials++
		}
	}

	if denials > 0 {
		return check.Result{
			Status:  check.Warn,
			Message: fmt.Sprintf("%d MAC denial(s) found in dmesg", denials),
			Remediation: "Review and fix MAC policy denials",
		}
	}
	return check.Result{Status: check.Pass, Message: "No MAC denials detected in dmesg"}
}
