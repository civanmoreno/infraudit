package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/spf13/cobra"
)

// ANSI escape codes for terminal output.
const (
	rst     = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
)

var explainRun bool

var explainCmd = &cobra.Command{
	Use:   "explain <CHECK-ID>",
	Short: "Explain a check in detail",
	Long: `Show detailed information about a specific check: what it verifies,
why it matters, how to remediate, and which compliance standard it maps to.

Use --run to also execute the check and show the current result.`,
	Args: cobra.ExactArgs(1),
	Run:  runExplain,
}

func init() {
	explainCmd.Flags().BoolVar(&explainRun, "run", false, "Also execute the check and show the result")
	rootCmd.AddCommand(explainCmd)
}

// cisMapping maps check IDs to CIS Benchmark control references.
var cisMapping = map[string]string{
	"AUTH-001": "CIS 5.2.10 — Ensure SSH root login is disabled",
	"AUTH-002": "CIS 5.2.12 — Ensure SSH PasswordAuthentication is disabled",
	"AUTH-003": "CIS 6.2.2 — Ensure root is the only UID 0 account",
	"AUTH-004": "CIS 6.2.1 — Ensure accounts in /etc/shadow use shadowed passwords",
	"AUTH-005": "CIS 5.6.2 — Ensure system accounts are secured",
	"AUTH-006": "CIS 5.3.4 — Ensure NOPASSWD is not used in sudoers",
	"AUTH-007": "CIS 6.1.2–6.1.4 — Ensure permissions on /etc/passwd, shadow, group",
	"AUTH-008": "CIS 5.6.4 — Ensure su command access is restricted",
	"PAM-001":  "CIS 5.4.1 — Ensure password creation requirements are configured",
	"PAM-002":  "CIS 5.4.3 — Ensure password reuse is limited",
	"PAM-003":  "CIS 5.4.2 — Ensure lockout for failed password attempts is configured",
	"PAM-004":  "CIS 5.4.2 — Ensure pam_faillock precedes pam_unix",
	"PAM-005":  "CIS 5.5.1.1–3 — Ensure password expiration policies are set",
	"NET-001":  "CIS 3.5.1 — Ensure a firewall is installed and active",
	"NET-002":  "CIS 3.5.3 — Ensure unnecessary open ports are not listening",
	"NET-003":  "CIS 3.2.1 — Ensure IP forwarding is disabled",
	"NET-004":  "CIS 3.2.2 — Ensure services bind to specific addresses",
	"SVC-001":  "CIS 2.1.1–2.1.6 — Ensure insecure services are not installed",
	"SVC-002":  "CIS 5.2.13–15 — Ensure SSH ciphers, MACs, and timeouts are configured",
	"SVC-007":  "CIS 2.2.4 — Ensure intrusion detection (fail2ban/crowdsec) is active",
	"SVC-008":  "CIS 5.6.3 — Review processes running as root",
	"FS-001":   "CIS 6.1.14 — Audit SUID/SGID executables",
	"FS-002":   "CIS 6.1.10 — Ensure no world-writable files exist",
	"FS-003":   "CIS 1.1.21 — Ensure sticky bit is set on world-writable directories",
	"FS-004":   "CIS 1.1.3–5 — Ensure nodev, nosuid, noexec on removable media and /tmp",
	"FS-005":   "CIS 1.1.15–17 — Ensure nodev, nosuid, noexec on /dev/shm",
	"FS-006":   "CIS 6.2.6 — Ensure home directories permissions are 750 or more restrictive",
	"FS-007":   "CIS 6.1.11–12 — Ensure no unowned or ungrouped files exist",
	"FS-008":   "CIS 1.1.6–14 — Ensure separate partitions for /tmp, /var, /var/log, /home",
	"LOG-001":  "CIS 4.2.1 — Ensure rsyslog/syslog-ng is installed and running",
	"LOG-002":  "CIS 4.1.1 — Ensure auditd is installed and running",
	"LOG-003":  "CIS 4.1.3–17 — Ensure audit rules for sensitive operations",
	"LOG-004":  "CIS 4.2.4 — Ensure logrotate is configured",
	"LOG-006":  "CIS 1.3.1 — Ensure AIDE is installed",
	"PKG-001":  "CIS 1.9 — Ensure updates and patches are installed",
	"PKG-004":  "CIS 1.9 — Ensure automatic security updates are enabled",
	"HARD-003": "CIS 1.5.1 — Ensure ASLR is enabled",
	"HARD-004": "CIS 1.5.2 — Ensure dmesg is restricted",
	"HARD-005": "CIS 1.5.3 — Ensure ptrace is restricted",
	"HARD-008": "CIS 1.1.1.1–7 — Ensure mounting of uncommon filesystems is disabled",
	"HARD-009": "CIS 1.1.1.8 — Ensure USB storage is disabled",
	"BOOT-001": "CIS 1.4.1 — Ensure bootloader password is set",
	"BOOT-002": "CIS 1.4.2 — Ensure bootloader configuration permissions",
	"BOOT-003": "CIS 1.4.3 — Ensure UEFI Secure Boot is enabled",
	"BOOT-004": "CIS 1.4.4 — Ensure authentication for single-user mode",
	"BOOT-005": "CIS 1.6.1 — Ensure SELinux or AppArmor is installed",
	"BOOT-006": "CIS 1.6.2 — Ensure SELinux/AppArmor is enforcing",
	"CRON-001": "CIS 5.1.1 — Ensure cron daemon is enabled",
	"CRON-002": "CIS 5.1.2 — Ensure permissions on /etc/crontab",
	"CRON-004": "CIS 5.1.8 — Ensure cron access is restricted (cron.allow)",
	"CRYPTO-002": "CIS 1.8 — Ensure certificates are not expired",
	"CRYPTO-004": "CIS 1.8 — Ensure TLS 1.0 and 1.1 are disabled",
	"CRYPTO-005": "CIS 1.8 — Ensure no weak cipher suites",
	"CRYPTO-007": "CIS 1.8 — Ensure private key file permissions",
	"CRYPTO-009": "CIS 6.3.4 — Ensure no MD5/SHA1 password hashes",
	"CTR-003":  "DISA STIG V-235810 — Ensure Docker socket permissions",
	"CTR-004":  "DISA STIG V-235818 — Ensure containers do not run as root",
	"CTR-005":  "DISA STIG V-235812 — Ensure no privileged containers",
}

// whyItMatters provides context on why a check is important.
var whyItMatters = map[string]string{
	"AUTH-001": "If root can log in directly via SSH, an attacker who obtains the root password gains immediate full access. Disabling root login forces use of named accounts with sudo, providing accountability and an extra authentication layer.",
	"AUTH-003": "Multiple accounts with UID 0 have unrestricted root access. This bypasses audit trails since actions cannot be attributed to a specific person.",
	"AUTH-004": "Accounts with empty passwords can be accessed by anyone with network or console access — no brute force needed.",
	"AUTH-005": "System accounts (daemon, bin, sys, etc.) with login shells can be exploited if their password is cracked or blank. Nologin shells prevent interactive logins.",
	"NET-001":  "Without a firewall, every listening service is directly exposed to the network. A firewall provides defense-in-depth even if individual services have vulnerabilities.",
	"NET-003":  "IP forwarding allows the server to route packets between networks. On non-router servers, this can enable attackers to use the compromised server as a pivot point.",
	"FS-001":   "SUID/SGID binaries run with elevated privileges. Unknown SUID files may be backdoors or vulnerable programs that allow privilege escalation.",
	"FS-002":   "World-writable files can be modified by any user. Attackers can alter scripts, configs, or data to escalate privileges or disrupt services.",
	"LOG-002":  "Without auditd, there is no record of security-relevant events (file access, privilege changes, login attempts). Forensic investigation after a breach becomes impossible.",
	"LOG-006":  "File integrity monitoring (AIDE) detects unauthorized changes to system files. Without it, rootkits and backdoors can persist undetected.",
	"BOOT-004": "If root has no password, anyone with physical or console access can boot into single-user/rescue mode and gain full root access without authentication.",
	"CRYPTO-007": "Private keys with loose permissions (readable by other users) can be stolen and used to impersonate the server or decrypt TLS traffic.",
	"CTR-005":  "Privileged containers have full access to the host kernel and devices. A container escape from a privileged container gives immediate root on the host.",
	"HARD-003": "ASLR randomizes memory addresses, making buffer overflow exploits significantly harder. Without it, exploits can reliably predict where code is loaded.",
}

func runExplain(cmd *cobra.Command, args []string) {
	id := strings.ToUpper(args[0])
	c := check.ByID(id)
	if c == nil {
		fmt.Fprintf(os.Stderr, "Check not found: %s\nRun 'infraudit list' to see all available checks.\n", id)
		os.Exit(1)
	}

	// Header
	fmt.Printf("\n  %s%s%s — %s\n", bold, c.ID(), rst, c.Name())
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("─", 60), rst)

	// Metadata
	fmt.Printf("  %sCategory:%s    %s\n", bold, rst, c.Category())
	fmt.Printf("  %sSeverity:%s    %s%s%s\n", bold, rst, severityColor(c.Severity()), c.Severity(), rst)
	fmt.Printf("  %sDescription:%s %s\n", bold, rst, c.Description())

	// CIS/STIG mapping
	if ref, ok := cisMapping[id]; ok {
		fmt.Printf("  %sStandard:%s    %s\n", bold, rst, ref)
	}
	fmt.Println()

	// Why it matters
	if why, ok := whyItMatters[id]; ok {
		fmt.Printf("  %sWhy it matters:%s\n", bold, rst)
		printWrapped(why, 60, "    ")
		fmt.Println()
	}

	// Run the check if requested
	if explainRun {
		fmt.Printf("  %sRunning check...%s\n\n", dim, rst)
		r := c.Run()
		statusClr := statusColor(r.Status.String())
		fmt.Printf("  %sResult:%s %s%s%s — %s\n", bold, rst, statusClr, r.Status, rst, r.Message)
		if r.Remediation != "" {
			fmt.Printf("\n  %sRemediation:%s\n", bold, rst)
			printWrapped(r.Remediation, 60, "    ")
		}
		if len(r.Details) > 0 {
			fmt.Printf("\n  %sDetails:%s\n", bold, rst)
			for k, v := range r.Details {
				fmt.Printf("    %s%s:%s %s\n", dim, k, rst, v)
			}
		}
		fmt.Println()
	}
}

func severityColor(s check.Severity) string {
	switch s {
	case check.Critical:
		return red + bold
	case check.High:
		return yellow
	case check.Medium:
		return cyan
	case check.Low:
		return blue
	default:
		return dim
	}
}

func statusColor(s string) string {
	switch s {
	case "PASS":
		return green + bold
	case "WARN":
		return yellow + bold
	case "FAIL":
		return red + bold
	case "ERROR":
		return magenta + bold
	default:
		return ""
	}
}

// printWrapped prints text wrapped at the given width with a prefix.
func printWrapped(text string, width int, prefix string) {
	words := strings.Fields(text)
	line := prefix
	for _, w := range words {
		if len(line)+len(w)+1 > width+len(prefix) && line != prefix {
			fmt.Println(line)
			line = prefix
		}
		if line == prefix {
			line += w
		} else {
			line += " " + w
		}
	}
	if line != prefix {
		fmt.Println(line)
	}
}
