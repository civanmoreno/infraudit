package packages

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&securityUpdates{})
	check.Register(&repoHTTPS{})
	check.Register(&kernelUpdate{})
	check.Register(&autoUpdates{})
}

// PKG-001
type securityUpdates struct{}

func (c *securityUpdates) ID() string               { return "PKG-001" }
func (c *securityUpdates) Name() string             { return "No pending security updates" }
func (c *securityUpdates) Category() string         { return "packages" }
func (c *securityUpdates) Severity() check.Severity { return check.High }
func (c *securityUpdates) Description() string      { return "Check for pending security updates" }

func (c *securityUpdates) Run() check.Result {
	// Try apt (Debian/Ubuntu)
	if _, err := exec.LookPath("apt"); err == nil {
		out, err := check.RunCmd(check.DefaultCmdTimeout, "apt", "list", "--upgradable")
		if err != nil {
			return check.Result{Status: check.Error, Message: "Failed to query apt: " + err.Error()}
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		var security int
		for _, l := range lines {
			if strings.Contains(l, "-security") {
				security++
			}
		}
		if security > 0 {
			return check.Result{
				Status:      check.Warn,
				Message:     fmt.Sprintf("%d security updates pending", security),
				Remediation: "Apply updates: 'apt update && apt upgrade'",
			}
		}
		return check.Result{Status: check.Pass, Message: "No pending security updates"}
	}

	// Try dnf (RHEL/Fedora)
	if _, err := exec.LookPath("dnf"); err == nil {
		out, err := check.RunCmd(check.DefaultCmdTimeout, "dnf", "check-update", "--security", "--quiet")
		// dnf check-update returns exit code 100 when updates available, 0 when none
		if err != nil && strings.TrimSpace(string(out)) == "" {
			return check.Result{Status: check.Error, Message: "Failed to query dnf: " + err.Error()}
		}
		if strings.TrimSpace(string(out)) != "" {
			return check.Result{
				Status:      check.Warn,
				Message:     "Security updates available via dnf",
				Remediation: "Apply: 'dnf update --security'",
			}
		}
		return check.Result{Status: check.Pass, Message: "No pending security updates"}
	}

	return check.Result{Status: check.Error, Message: "No supported package manager found (apt/dnf)"}
}

// PKG-002
type repoHTTPS struct{}

func (c *repoHTTPS) ID() string               { return "PKG-002" }
func (c *repoHTTPS) Name() string             { return "Package repositories use HTTPS" }
func (c *repoHTTPS) Category() string         { return "packages" }
func (c *repoHTTPS) Severity() check.Severity { return check.Medium }
func (c *repoHTTPS) Description() string      { return "Verify package repos use secure transport" }

func (c *repoHTTPS) Run() check.Result {
	// Check apt sources
	paths := []string{check.P("/etc/apt/sources.list")}
	entries, _ := os.ReadDir(check.P("/etc/apt/sources.list.d"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".list") || strings.HasSuffix(e.Name(), ".sources") {
			paths = append(paths, check.P("/etc/apt/sources.list.d/"+e.Name()))
		}
	}

	var insecure []string
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "http://") && !strings.Contains(line, "https://") {
				insecure = append(insecure, p)
				break
			}
		}
	}

	// Check yum/dnf repos
	yumEntries, _ := os.ReadDir(check.P("/etc/yum.repos.d"))
	for _, e := range yumEntries {
		if !strings.HasSuffix(e.Name(), ".repo") {
			continue
		}
		data, err := os.ReadFile(check.P("/etc/yum.repos.d/" + e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "baseurl=http://") {
			insecure = append(insecure, e.Name())
		}
	}

	if len(insecure) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "HTTP repos found in: " + strings.Join(insecure, ", "),
			Remediation: "Change repository URLs from http:// to https://",
		}
	}
	return check.Result{Status: check.Pass, Message: "All repositories use HTTPS"}
}

// PKG-003
type kernelUpdate struct{}

func (c *kernelUpdate) ID() string               { return "PKG-003" }
func (c *kernelUpdate) Name() string             { return "Kernel is up to date" }
func (c *kernelUpdate) Category() string         { return "packages" }
func (c *kernelUpdate) Severity() check.Severity { return check.High }
func (c *kernelUpdate) Description() string      { return "Check if a newer kernel is available" }

func (c *kernelUpdate) Run() check.Result {
	// Check if reboot required (kernel was updated but not rebooted)
	if _, err := os.Stat(check.P("/var/run/reboot-required")); err == nil {
		return check.Result{
			Status:      check.Warn,
			Message:     "System reboot required (likely kernel update pending)",
			Remediation: "Schedule a system reboot to apply the new kernel",
		}
	}
	return check.Result{Status: check.Pass, Message: "No reboot required for kernel updates"}
}

// PKG-004
type autoUpdates struct{}

func (c *autoUpdates) ID() string               { return "PKG-004" }
func (c *autoUpdates) Name() string             { return "Automatic security updates enabled" }
func (c *autoUpdates) Category() string         { return "packages" }
func (c *autoUpdates) Severity() check.Severity { return check.Medium }
func (c *autoUpdates) Description() string {
	return "Verify unattended-upgrades or dnf-automatic is configured"
}
func (c *autoUpdates) RequiredInit() string { return "systemd" }

func (c *autoUpdates) Run() check.Result {
	// Check unattended-upgrades (Debian/Ubuntu)
	if check.ServiceActive("unattended-upgrades") || check.ServiceActive("apt-daily-upgrade.timer") {
		return check.Result{Status: check.Pass, Message: "unattended-upgrades is active"}
	}

	// Check dnf-automatic (RHEL/Fedora)
	if check.ServiceActive("dnf-automatic.timer") || check.ServiceActive("dnf-automatic-install.timer") {
		return check.Result{Status: check.Pass, Message: "dnf-automatic is active"}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "Automatic security updates are not configured",
		Remediation: "Enable: 'apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades'",
	}
}
