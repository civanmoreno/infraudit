package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/version"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check system readiness for auditing",
	Long: `Diagnose system readiness before running an audit. Shows what tools
are available, what permissions you have, and which check categories
will work correctly.

Run this first to understand why certain checks might return ERROR.`,
	Run: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

type toolCheck struct {
	Name        string
	Binary      string
	Required    bool
	Description string
}

func runDoctor(_ *cobra.Command, _ []string) {
	fmt.Printf("\n  %sinfraudit doctor%s v%s\n", bold, rst, version.Version)
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("─", 50), rst)

	// System info
	printSection("System")
	hostname, _ := os.Hostname()
	fmt.Printf("  Hostname:      %s\n", hostname)
	fmt.Printf("  Architecture:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  Running as:    %s\n", currentUser())
	fmt.Printf("  Root access:   %s\n", boolStatus(os.Getuid() == 0))
	fmt.Println()

	if os.Getuid() != 0 {
		fmt.Printf("  %s⚠  Run as root (sudo) for full audit results%s\n\n", yellow, rst)
	}

	// Core tools
	printSection("Core Tools")
	coreTools := []toolCheck{
		{"systemctl", "systemctl", true, "Service management (used by 20+ checks)"},
		{"find", "find", true, "Filesystem scanning (SUID, world-writable, orphaned files)"},
		{"awk", "awk", true, "Text processing for config parsing"},
		{"grep", "grep", true, "Pattern matching in config files"},
		{"ss", "ss", false, "Socket statistics (network checks)"},
	}
	checkTools(coreTools)

	// Security tools
	printSection("Security Tools")
	secTools := []toolCheck{
		{"auditd (auditctl)", "auditctl", false, "Audit framework — LOG checks"},
		{"fail2ban", "fail2ban-client", false, "Intrusion prevention — SVC-007"},
		{"aide", "aide", false, "File integrity monitoring — LOG-006"},
		{"rkhunter", "rkhunter", false, "Rootkit detection — MAL-001"},
		{"ClamAV (clamscan)", "clamscan", false, "Antivirus scanning — MAL-003"},
	}
	checkTools(secTools)

	// Firewall tools
	printSection("Firewall")
	fwTools := []toolCheck{
		{"ufw", "ufw", false, "Uncomplicated Firewall"},
		{"nftables (nft)", "nft", false, "Netfilter tables"},
		{"iptables", "iptables", false, "Legacy firewall"},
	}
	fwFound := checkTools(fwTools)
	if fwFound == 0 {
		fmt.Printf("  %s⚠  No firewall tool detected — NET-001 will FAIL%s\n", yellow, rst)
	}
	fmt.Println()

	// Container runtime
	printSection("Container Runtime")
	ctrTools := []toolCheck{
		{"Docker", "docker", false, "Docker container runtime"},
		{"Podman", "podman", false, "Podman container runtime"},
	}
	ctrFound := checkTools(ctrTools)
	if ctrFound == 0 {
		fmt.Printf("  %sℹ  No container runtime — CTR checks will auto-pass%s\n", dim, rst)
	}
	fmt.Println()

	// Time sync
	printSection("Time Synchronization")
	timeTools := []toolCheck{
		{"chronyc", "chronyc", false, "Chrony NTP client"},
		{"ntpq", "ntpq", false, "NTP query tool"},
		{"timedatectl", "timedatectl", false, "Systemd time control"},
	}
	checkTools(timeTools)

	// Boot & MAC
	printSection("Boot & MAC")
	bootTools := []toolCheck{
		{"mokutil", "mokutil", false, "Secure Boot verification"},
		{"aa-status", "aa-status", false, "AppArmor status"},
		{"getenforce", "getenforce", false, "SELinux status"},
	}
	checkTools(bootTools)

	// Backup tools
	printSection("Backup Tools")
	bkTools := []toolCheck{
		{"restic", "restic", false, "Restic backup"},
		{"borg", "borg", false, "Borg backup"},
		{"duplicity", "duplicity", false, "Duplicity backup"},
	}
	bkFound := checkTools(bkTools)
	if bkFound == 0 {
		fmt.Printf("  %sℹ  No backup tool — BAK checks will WARN%s\n", dim, rst)
	}
	fmt.Println()

	// SSH tools (for remote scanning)
	printSection("Remote Scanning (infraudit scan)")
	sshTools := []toolCheck{
		{"ssh", "ssh", false, "SSH client for remote scanning"},
		{"scp", "scp", false, "Secure copy for binary deployment"},
		{"sshpass", "sshpass", false, "Password-based SSH (optional)"},
	}
	checkTools(sshTools)

	// Category readiness summary
	printSection("Category Readiness")
	printCategoryReadiness()

	// Check count
	total := len(check.All())
	fmt.Printf("\n  %sRegistered checks:%s %d across %d categories\n",
		bold, rst, total, countCategories())
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("─", 50), rst)
}

func printSection(name string) {
	fmt.Printf("  %s%s%s\n", cyan+bold, name, rst)
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 50), rst)
}

func checkTools(tools []toolCheck) int {
	found := 0
	for _, t := range tools {
		_, err := exec.LookPath(t.Binary)
		if err == nil {
			found++
			fmt.Printf("  %s✓%s %-22s %s%s%s\n", green, rst, t.Name, dim, t.Description, rst)
		} else {
			icon := yellow + "○" + rst
			label := "not found"
			if t.Required {
				icon = red + "✗" + rst
				label = "MISSING"
			}
			fmt.Printf("  %s %-22s %s%s — %s%s\n", icon, t.Name, dim, label, t.Description, rst)
		}
	}
	fmt.Println()
	return found
}

func boolStatus(b bool) string {
	if b {
		return green + "yes" + rst
	}
	return yellow + "no" + rst
}

func currentUser() string {
	if os.Getuid() == 0 {
		return green + "root" + rst
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}
	return yellow + user + rst
}

func printCategoryReadiness() {
	categories := []struct {
		name  string
		label string
		needs []string // binaries needed for best results
	}{
		{"auth", "Users & Authentication", nil},
		{"pam", "Password Policies", nil},
		{"network", "Network & Firewall", []string{"ufw", "nft", "iptables"}},
		{"services", "Services & Processes", []string{"systemctl"}},
		{"filesystem", "Filesystem & Permissions", []string{"find"}},
		{"logging", "Logging & Auditing", []string{"auditctl"}},
		{"packages", "Packages & Updates", []string{"apt", "dnf"}},
		{"hardening", "Kernel Hardening", nil},
		{"boot", "Boot Security & MAC", []string{"mokutil"}},
		{"cron", "Scheduled Jobs", nil},
		{"crypto", "TLS/SSL & Cryptography", []string{"openssl"}},
		{"secrets", "Secrets & Credentials", nil},
		{"container", "Container Security", []string{"docker", "podman"}},
		{"rlimit", "Resource Limits", []string{"df"}},
		{"nfs", "Network Filesystems", nil},
		{"malware", "Rootkits & Malware", []string{"rkhunter", "clamscan"}},
		{"backup", "Backups", []string{"restic", "borg", "duplicity"}},
	}

	for _, cat := range categories {
		icon := green + "✓" + rst
		status := "ready"

		if len(cat.needs) > 0 {
			anyFound := false
			for _, bin := range cat.needs {
				if _, err := exec.LookPath(bin); err == nil {
					anyFound = true
					break
				}
			}
			if !anyFound {
				icon = yellow + "~" + rst
				status = "limited (no " + strings.Join(cat.needs, "/") + ")"
			}
		}

		if os.Getuid() != 0 {
			switch cat.name {
			case "auth", "pam", "logging", "boot", "crypto":
				icon = yellow + "~" + rst
				status = "limited (needs root)"
			}
		}

		fmt.Printf("  %s %-10s %-28s %s%s%s\n",
			icon, strings.ToUpper(cat.name[:1])+cat.name[1:], cat.label, dim, status, rst)
	}
}

func countCategories() int {
	cats := map[string]bool{}
	for _, c := range check.All() {
		cats[c.Category()] = true
	}
	return len(cats)
}
