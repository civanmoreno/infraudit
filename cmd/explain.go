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
	Args:              cobra.ExactArgs(1),
	Run:               runExplain,
	ValidArgsFunction: completeCheckIDs,
}

func init() {
	explainCmd.Flags().BoolVar(&explainRun, "run", false, "Also execute the check and show the result")
	rootCmd.AddCommand(explainCmd)
}

// completeCheckIDs provides shell completion for check IDs.
func completeCheckIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	upper := strings.ToUpper(toComplete)
	var matches []string
	for _, c := range check.All() {
		id := c.ID()
		if strings.HasPrefix(id, upper) {
			matches = append(matches, id+"\t"+c.Name())
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

// cisMapping maps check IDs to CIS Benchmark control references.
var cisMapping = map[string]string{
	"AUTH-001":   "CIS 5.2.10 — Ensure SSH root login is disabled",
	"AUTH-002":   "CIS 5.2.12 — Ensure SSH PasswordAuthentication is disabled",
	"AUTH-003":   "CIS 6.2.2 — Ensure root is the only UID 0 account",
	"AUTH-004":   "CIS 6.2.1 — Ensure accounts in /etc/shadow use shadowed passwords",
	"AUTH-005":   "CIS 5.6.2 — Ensure system accounts are secured",
	"AUTH-006":   "CIS 5.3.4 — Ensure NOPASSWD is not used in sudoers",
	"AUTH-007":   "CIS 6.1.2–6.1.4 — Ensure permissions on /etc/passwd, shadow, group",
	"AUTH-008":   "CIS 5.6.4 — Ensure su command access is restricted",
	"PAM-001":    "CIS 5.4.1 — Ensure password creation requirements are configured",
	"PAM-002":    "CIS 5.4.3 — Ensure password reuse is limited",
	"PAM-003":    "CIS 5.4.2 — Ensure lockout for failed password attempts is configured",
	"PAM-004":    "CIS 5.4.2 — Ensure pam_faillock precedes pam_unix",
	"PAM-005":    "CIS 5.5.1.1–3 — Ensure password expiration policies are set",
	"NET-001":    "CIS 3.5.1 — Ensure a firewall is installed and active",
	"NET-002":    "CIS 3.5.3 — Ensure unnecessary open ports are not listening",
	"NET-003":    "CIS 3.2.1 — Ensure IP forwarding is disabled",
	"NET-004":    "CIS 3.2.2 — Ensure services bind to specific addresses",
	"SVC-001":    "CIS 2.1.1–2.1.6 — Ensure insecure services are not installed",
	"SVC-002":    "CIS 5.2.13–15 — Ensure SSH ciphers, MACs, and timeouts are configured",
	"SVC-007":    "CIS 2.2.4 — Ensure intrusion detection (fail2ban/crowdsec) is active",
	"SVC-008":    "CIS 5.6.3 — Review processes running as root",
	"FS-001":     "CIS 6.1.14 — Audit SUID/SGID executables",
	"FS-002":     "CIS 6.1.10 — Ensure no world-writable files exist",
	"FS-003":     "CIS 1.1.21 — Ensure sticky bit is set on world-writable directories",
	"FS-004":     "CIS 1.1.3–5 — Ensure nodev, nosuid, noexec on removable media and /tmp",
	"FS-005":     "CIS 1.1.15–17 — Ensure nodev, nosuid, noexec on /dev/shm",
	"FS-006":     "CIS 6.2.6 — Ensure home directories permissions are 750 or more restrictive",
	"FS-007":     "CIS 6.1.11–12 — Ensure no unowned or ungrouped files exist",
	"FS-008":     "CIS 1.1.6–14 — Ensure separate partitions for /tmp, /var, /var/log, /home",
	"LOG-001":    "CIS 4.2.1 — Ensure rsyslog/syslog-ng is installed and running",
	"LOG-002":    "CIS 4.1.1 — Ensure auditd is installed and running",
	"LOG-003":    "CIS 4.1.3–17 — Ensure audit rules for sensitive operations",
	"LOG-004":    "CIS 4.2.4 — Ensure logrotate is configured",
	"LOG-006":    "CIS 1.3.1 — Ensure AIDE is installed",
	"PKG-001":    "CIS 1.9 — Ensure updates and patches are installed",
	"PKG-004":    "CIS 1.9 — Ensure automatic security updates are enabled",
	"HARD-003":   "CIS 1.5.1 — Ensure ASLR is enabled",
	"HARD-004":   "CIS 1.5.2 — Ensure dmesg is restricted",
	"HARD-005":   "CIS 1.5.3 — Ensure ptrace is restricted",
	"HARD-008":   "CIS 1.1.1.1–7 — Ensure mounting of uncommon filesystems is disabled",
	"HARD-009":   "CIS 1.1.1.8 — Ensure USB storage is disabled",
	"BOOT-001":   "CIS 1.4.1 — Ensure bootloader password is set",
	"BOOT-002":   "CIS 1.4.2 — Ensure bootloader configuration permissions",
	"BOOT-003":   "CIS 1.4.3 — Ensure UEFI Secure Boot is enabled",
	"BOOT-004":   "CIS 1.4.4 — Ensure authentication for single-user mode",
	"BOOT-005":   "CIS 1.6.1 — Ensure SELinux or AppArmor is installed",
	"BOOT-006":   "CIS 1.6.2 — Ensure SELinux/AppArmor is enforcing",
	"CRON-001":   "CIS 5.1.1 — Ensure cron daemon is enabled",
	"CRON-002":   "CIS 5.1.2 — Ensure permissions on /etc/crontab",
	"CRON-004":   "CIS 5.1.8 — Ensure cron access is restricted (cron.allow)",
	"CRYPTO-002": "CIS 1.8 — Ensure certificates are not expired",
	"CRYPTO-004": "CIS 1.8 — Ensure TLS 1.0 and 1.1 are disabled",
	"CRYPTO-005": "CIS 1.8 — Ensure no weak cipher suites",
	"CRYPTO-007": "CIS 1.8 — Ensure private key file permissions",
	"CRYPTO-009": "CIS 6.3.4 — Ensure no MD5/SHA1 password hashes",
	"CTR-003":    "DISA STIG V-235810 — Ensure Docker socket permissions",
	"CTR-004":    "DISA STIG V-235818 — Ensure containers do not run as root",
	"CTR-005":    "DISA STIG V-235812 — Ensure no privileged containers",
}

// whyItMatters provides context on why a check is important.
var whyItMatters = map[string]string{
	"AUTH-001":   "If root can log in directly via SSH, an attacker who obtains the root password gains immediate full access. Disabling root login forces use of named accounts with sudo, providing accountability and an extra authentication layer.",
	"AUTH-002":   "Password-based SSH authentication is vulnerable to brute-force attacks. Key-based authentication is significantly more secure and should be the only method allowed.",
	"AUTH-003":   "Multiple accounts with UID 0 have unrestricted root access. This bypasses audit trails since actions cannot be attributed to a specific person.",
	"AUTH-004":   "Accounts with empty passwords can be accessed by anyone with network or console access — no brute force needed.",
	"AUTH-005":   "System accounts (daemon, bin, sys, etc.) with login shells can be exploited if their password is cracked or blank. Nologin shells prevent interactive logins.",
	"AUTH-006":   "NOPASSWD entries in sudoers allow privilege escalation without re-authentication. If a user session is hijacked, the attacker gets sudo access with no additional barrier.",
	"AUTH-007":   "Incorrect permissions on /etc/passwd, /etc/shadow, or /etc/group can allow unauthorized users to read password hashes or modify account information.",
	"AUTH-008":   "Unrestricted su access allows any user to attempt to become root. Limiting su to a specific group (wheel) reduces the attack surface.",
	"PAM-001":    "Weak password requirements make brute-force and dictionary attacks feasible. Strong complexity rules force users to choose harder-to-crack passwords.",
	"PAM-002":    "Without password reuse limits, users cycle through the same weak passwords. Enforcing history prevents reuse of recently compromised passwords.",
	"PAM-003":    "Without account lockout, attackers can attempt unlimited password guesses. Lockout policies stop brute-force attacks after a set number of failures.",
	"PAM-005":    "Passwords that never expire remain valid indefinitely. If compromised, they provide persistent access until manually changed.",
	"NET-001":    "Without a firewall, every listening service is directly exposed to the network. A firewall provides defense-in-depth even if individual services have vulnerabilities.",
	"NET-002":    "Unnecessary open ports increase the attack surface. Each listening service is a potential entry point for exploitation.",
	"NET-003":    "IP forwarding allows the server to route packets between networks. On non-router servers, this can enable attackers to use the compromised server as a pivot point.",
	"NET-004":    "Services binding to 0.0.0.0 are accessible from all network interfaces. Binding to specific addresses limits exposure to only intended networks.",
	"NET-008":    "IPv6 that is enabled but not properly configured can be exploited for network attacks (MITM, rogue router advertisements) while being overlooked by IPv4-only monitoring.",
	"SVC-001":    "Legacy services like telnet, rsh, and rlogin transmit credentials in cleartext. They should be replaced with SSH.",
	"SVC-002":    "Weak SSH ciphers and MACs can be broken by attackers to decrypt or tamper with SSH sessions. Only strong algorithms should be allowed.",
	"SVC-007":    "Without intrusion detection (fail2ban/crowdsec), brute-force SSH attacks can run indefinitely. These tools automatically ban attacking IPs.",
	"SVC-008":    "Processes running as root have unrestricted system access. Minimizing root processes reduces the impact of any single service compromise.",
	"FS-001":     "SUID/SGID binaries run with elevated privileges. Unknown SUID files may be backdoors or vulnerable programs that allow privilege escalation.",
	"FS-002":     "World-writable files can be modified by any user. Attackers can alter scripts, configs, or data to escalate privileges or disrupt services.",
	"FS-003":     "Without the sticky bit on world-writable directories, any user can delete or rename files owned by others, enabling denial of service or data tampering.",
	"FS-005":     "/dev/shm without nodev/nosuid/noexec allows attackers to create device files, SUID binaries, or execute code from shared memory — a common post-exploitation technique.",
	"FS-006":     "Home directories with excessive permissions allow other users to read SSH keys, shell history, and personal configs, enabling lateral movement.",
	"FS-007":     "Orphaned files (no valid owner/group) may belong to deleted accounts. They can be claimed by new accounts that reuse the same UID/GID, granting unintended access.",
	"FS-008":     "Without separate partitions, a full /var/log or /tmp can fill the root filesystem, causing system-wide denial of service.",
	"LOG-001":    "Without syslog, system events are not collected centrally. Security incidents, service failures, and authentication events go unrecorded.",
	"LOG-002":    "Without auditd, there is no record of security-relevant events (file access, privilege changes, login attempts). Forensic investigation after a breach becomes impossible.",
	"LOG-003":    "Without audit rules for sensitive operations (user/group changes, sudo usage, file deletions), malicious activity leaves no trace in audit logs.",
	"LOG-004":    "Without logrotate, log files grow unbounded, eventually filling the disk and causing denial of service or loss of recent log entries.",
	"LOG-006":    "File integrity monitoring (AIDE) detects unauthorized changes to system files. Without it, rootkits and backdoors can persist undetected.",
	"PKG-001":    "Unpatched systems are vulnerable to known exploits. Public CVEs have readily available exploit code that attackers use within hours of disclosure.",
	"PKG-004":    "Without automatic security updates, critical patches require manual intervention. Delays between patch availability and application create a window of vulnerability.",
	"HARD-003":   "ASLR randomizes memory addresses, making buffer overflow exploits significantly harder. Without it, exploits can reliably predict where code is loaded.",
	"HARD-004":   "Unrestricted dmesg access leaks kernel addresses and hardware info that helps attackers craft targeted exploits.",
	"HARD-005":   "Unrestricted ptrace allows any process to inspect and modify other processes' memory, enabling credential theft and code injection.",
	"HARD-008":   "Uncommon filesystems (cramfs, freevxfs, hfs, etc.) are rarely needed and may have unpatched vulnerabilities. Disabling them reduces kernel attack surface.",
	"HARD-009":   "USB storage devices can introduce malware or be used to exfiltrate data. Disabling USB storage on servers eliminates this physical attack vector.",
	"BOOT-001":   "Without a bootloader password, anyone with physical access can modify boot parameters to gain root access (e.g., init=/bin/bash).",
	"BOOT-002":   "If GRUB config files are world-readable, attackers can read boot parameters, kernel versions, and partition layouts to plan targeted attacks.",
	"BOOT-003":   "Without Secure Boot, an attacker with physical access can boot a modified kernel or bootloader (bootkit), persisting below the OS level.",
	"BOOT-004":   "If root has no password, anyone with physical or console access can boot into single-user/rescue mode and gain full root access without authentication.",
	"BOOT-005":   "Without a Mandatory Access Control system (SELinux/AppArmor), a compromised process has access to everything its user can reach. MAC confines processes to only the resources they need.",
	"BOOT-006":   "SELinux/AppArmor in permissive mode only logs violations without enforcing them, providing zero protection against actual attacks.",
	"CRON-001":   "If cron is disabled, scheduled security tasks (log rotation, AIDE scans, certificate renewal) stop running silently.",
	"CRON-002":   "Loose permissions on /etc/crontab allow unprivileged users to schedule root-level commands, leading to trivial privilege escalation.",
	"CRON-004":   "Without cron.allow, any user can create cron jobs. Attackers with low-privilege access can establish persistence via cron.",
	"CRYPTO-002": "Expired certificates cause service outages and browser warnings. They also indicate neglected PKI management, which may mask other certificate issues.",
	"CRYPTO-004": "TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE). Modern clients support TLS 1.2+, so older versions should be disabled.",
	"CRYPTO-005": "Weak cipher suites (RC4, DES, export ciphers) can be broken to decrypt traffic. Only strong ciphers should be configured.",
	"CRYPTO-007": "Private keys with loose permissions (readable by other users) can be stolen and used to impersonate the server or decrypt TLS traffic.",
	"CRYPTO-009": "MD5 and SHA1 password hashes are computationally cheap to crack. Modern algorithms (SHA-512, yescrypt) provide significantly stronger protection.",
	"CTR-003":    "The Docker socket grants full control over the Docker daemon. If accessible to non-root users, they can mount the host filesystem and gain root access.",
	"CTR-004":    "Containers running as root inside the container can exploit kernel vulnerabilities to escape and become root on the host.",
	"CTR-005":    "Privileged containers have full access to the host kernel and devices. A container escape from a privileged container gives immediate root on the host.",
	"CTR-006":    "Containers without resource limits can consume all host CPU/memory, causing denial of service to other containers and the host itself.",
	"BAK-001":    "Without verified backups, a ransomware attack or disk failure results in permanent data loss. Backups are the last line of defense.",
	"MAL-001":    "Without antivirus scanning (ClamAV), malware uploaded to the server or introduced via compromised packages goes undetected.",
	"SEC-001":    "Secrets (API keys, passwords) in environment variables are exposed in /proc, docker inspect, and crash dumps. They should be stored in dedicated secret managers.",
}

// remediationSteps provides copy-paste ready commands for each check.
var remediationSteps = map[string][]string{
	"AUTH-001": {
		"sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
		"systemctl restart sshd",
	},
	"AUTH-002": {
		"sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
		"systemctl restart sshd",
	},
	"AUTH-003": {
		"# Identify accounts with UID 0 (only root should have it):",
		"awk -F: '$3 == 0 {print $1}' /etc/passwd",
		"# Change UID of non-root accounts or remove them:",
		"usermod -u <NEW_UID> <username>",
	},
	"AUTH-004": {
		"# Lock accounts with empty passwords:",
		"passwd -l <username>",
		"# Or set a strong password:",
		"passwd <username>",
	},
	"AUTH-005": {
		"# Set nologin shell for system accounts:",
		"usermod -s /usr/sbin/nologin <account>",
	},
	"AUTH-006": {
		"# Edit sudoers and remove NOPASSWD entries:",
		"visudo",
		"# Change lines like: user ALL=(ALL) NOPASSWD: ALL",
		"# To:                user ALL=(ALL) ALL",
	},
	"AUTH-007": {
		"chmod 644 /etc/passwd",
		"chmod 640 /etc/shadow",
		"chmod 644 /etc/group",
		"chown root:root /etc/passwd /etc/group",
		"chown root:shadow /etc/shadow",
	},
	"AUTH-008": {
		"# Uncomment or add in /etc/pam.d/su:",
		"# auth required pam_wheel.so use_uid",
		"usermod -aG wheel <trusted_user>",
	},
	"PAM-001": {
		"# Install libpam-pwquality if not present:",
		"apt install libpam-pwquality   # Debian/Ubuntu",
		"yum install pam_pwquality      # RHEL/CentOS",
		"# Edit /etc/security/pwquality.conf:",
		"minlen = 14",
		"minclass = 4",
	},
	"PAM-003": {
		"# Add to /etc/pam.d/common-auth (Debian) or /etc/pam.d/system-auth (RHEL):",
		"auth required pam_faillock.so preauth deny=5 unlock_time=900",
		"auth required pam_faillock.so authfail deny=5 unlock_time=900",
	},
	"PAM-005": {
		"# Edit /etc/login.defs:",
		"PASS_MAX_DAYS   365",
		"PASS_MIN_DAYS   7",
		"PASS_WARN_AGE   14",
	},
	"NET-001": {
		"# Enable firewall (UFW):",
		"ufw enable",
		"# Or with firewalld:",
		"systemctl enable --now firewalld",
	},
	"NET-003": {
		"sysctl -w net.ipv4.ip_forward=0",
		"echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-security.conf",
		"sysctl --system",
	},
	"NET-008": {
		"# Disable IPv6 if not needed:",
		"sysctl -w net.ipv6.conf.all.disable_ipv6=1",
		"echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.d/99-security.conf",
	},
	"SVC-001": {
		"# Remove insecure services:",
		"apt purge telnet rsh-client rlogin   # Debian/Ubuntu",
		"yum remove telnet rsh                # RHEL/CentOS",
	},
	"SVC-002": {
		"# Add to /etc/ssh/sshd_config:",
		"Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr",
		"MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
		"KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512",
		"systemctl restart sshd",
	},
	"SVC-007": {
		"# Install and enable fail2ban:",
		"apt install fail2ban   # Debian/Ubuntu",
		"yum install fail2ban   # RHEL/CentOS",
		"systemctl enable --now fail2ban",
	},
	"FS-001": {
		"# Review SUID/SGID files and remove the bit if unnecessary:",
		"find / -perm /6000 -type f 2>/dev/null",
		"chmod u-s /path/to/unnecessary/suid/binary",
		"chmod g-s /path/to/unnecessary/sgid/binary",
	},
	"FS-002": {
		"# Find and fix world-writable files:",
		"find / -xdev -type f -perm -0002 2>/dev/null",
		"chmod o-w /path/to/file",
	},
	"FS-003": {
		"# Set sticky bit on world-writable directories:",
		"find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null",
		"chmod +t /path/to/directory",
	},
	"FS-005": {
		"# Add options to /etc/fstab for /dev/shm:",
		"tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0",
		"mount -o remount /dev/shm",
	},
	"FS-006": {
		"# Fix home directory permissions:",
		"chmod 750 /home/<user>",
	},
	"FS-007": {
		"# Find orphaned files and assign ownership:",
		"find / -xdev -nouser -o -nogroup 2>/dev/null",
		"chown root:root /path/to/orphaned/file",
	},
	"FS-008": {
		"# Create separate partitions in /etc/fstab:",
		"# /tmp, /var, /var/log, /var/log/audit, /home",
		"# This requires disk partitioning — plan during provisioning.",
	},
	"LOG-001": {
		"# Install and enable rsyslog:",
		"apt install rsyslog   # Debian/Ubuntu",
		"yum install rsyslog   # RHEL/CentOS",
		"systemctl enable --now rsyslog",
	},
	"LOG-002": {
		"# Install and enable auditd:",
		"apt install auditd    # Debian/Ubuntu",
		"yum install audit      # RHEL/CentOS",
		"systemctl enable --now auditd",
	},
	"LOG-003": {
		"# Add audit rules to /etc/audit/rules.d/audit.rules:",
		"-w /etc/passwd -p wa -k identity",
		"-w /etc/shadow -p wa -k identity",
		"-w /etc/sudoers -p wa -k actions",
		"-a always,exit -F arch=b64 -S execve -k exec",
		"augenrules --load",
	},
	"LOG-004": {
		"# Install logrotate (usually pre-installed):",
		"apt install logrotate   # Debian/Ubuntu",
		"# Verify config exists:",
		"cat /etc/logrotate.conf",
	},
	"LOG-006": {
		"# Install and initialize AIDE:",
		"apt install aide     # Debian/Ubuntu",
		"yum install aide     # RHEL/CentOS",
		"aide --init",
		"mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
	},
	"PKG-001": {
		"# Update all packages:",
		"apt update && apt upgrade   # Debian/Ubuntu",
		"yum update                  # RHEL/CentOS",
	},
	"PKG-004": {
		"# Enable automatic security updates:",
		"apt install unattended-upgrades   # Debian/Ubuntu",
		"dpkg-reconfigure -plow unattended-upgrades",
		"# Or for RHEL/CentOS:",
		"yum install dnf-automatic",
		"systemctl enable --now dnf-automatic.timer",
	},
	"HARD-003": {
		"sysctl -w kernel.randomize_va_space=2",
		"echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-security.conf",
	},
	"HARD-004": {
		"sysctl -w kernel.dmesg_restrict=1",
		"echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/99-security.conf",
	},
	"HARD-005": {
		"sysctl -w kernel.yama.ptrace_scope=1",
		"echo 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/99-security.conf",
	},
	"HARD-009": {
		"echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf",
		"rmmod usb-storage 2>/dev/null || true",
	},
	"BOOT-001": {
		"# Generate GRUB password hash:",
		"grub-mkpasswd-pbkdf2",
		"# Add to /etc/grub.d/40_custom:",
		"set superusers=\"admin\"",
		"password_pbkdf2 admin <hash>",
		"update-grub",
	},
	"BOOT-002": {
		"chmod 600 /boot/grub/grub.cfg",
		"chown root:root /boot/grub/grub.cfg",
	},
	"BOOT-004": {
		"# Set root password if not set:",
		"passwd root",
	},
	"BOOT-005": {
		"# Install AppArmor (Debian/Ubuntu):",
		"apt install apparmor apparmor-utils",
		"# Or SELinux (RHEL/CentOS — usually pre-installed):",
		"yum install selinux-policy-targeted",
	},
	"BOOT-006": {
		"# Set SELinux to enforcing:",
		"setenforce 1",
		"sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
		"# Or for AppArmor:",
		"aa-enforce /etc/apparmor.d/*",
	},
	"CRON-002": {
		"chmod 600 /etc/crontab",
		"chown root:root /etc/crontab",
	},
	"CRON-004": {
		"# Create /etc/cron.allow with permitted users:",
		"echo root > /etc/cron.allow",
		"chmod 640 /etc/cron.allow",
		"# Remove cron.deny if it exists:",
		"rm -f /etc/cron.deny",
	},
	"CRYPTO-004": {
		"# Disable TLS 1.0/1.1 in OpenSSL config (/etc/ssl/openssl.cnf):",
		"[system_default_sect]",
		"MinProtocol = TLSv1.2",
	},
	"CRYPTO-007": {
		"# Fix private key permissions:",
		"chmod 600 /path/to/private.key",
		"chown root:root /path/to/private.key",
	},
	"CRYPTO-009": {
		"# Force password hash upgrade by requiring password change:",
		"chage -d 0 <username>",
		"# Ensure /etc/login.defs uses strong algorithm:",
		"ENCRYPT_METHOD SHA512",
	},
	"CTR-003": {
		"chmod 660 /var/run/docker.sock",
		"chown root:docker /var/run/docker.sock",
	},
	"CTR-004": {
		"# Add USER directive to Dockerfiles:",
		"# USER nonroot",
		"# Or run with --user flag:",
		"docker run --user 1000:1000 <image>",
	},
	"CTR-005": {
		"# Remove --privileged flag and use specific capabilities:",
		"docker run --cap-add NET_ADMIN <image>",
		"# Instead of: docker run --privileged <image>",
	},
	"CTR-006": {
		"# Set resource limits when running containers:",
		"docker run --memory=512m --cpus=1 <image>",
	},
}

// verifyFix provides commands to verify a remediation was applied correctly.
var verifyFix = map[string]string{
	"AUTH-001":   "sshd -T | grep -i permitrootlogin\n  Expected: permitrootlogin no",
	"AUTH-002":   "sshd -T | grep -i passwordauthentication\n  Expected: passwordauthentication no",
	"AUTH-003":   "awk -F: '$3 == 0 {print $1}' /etc/passwd\n  Expected: only 'root'",
	"AUTH-004":   "awk -F: '$2 == \"\" {print $1}' /etc/shadow\n  Expected: no output",
	"AUTH-005":   "awk -F: '$3 < 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd\n  Expected: only 'root'",
	"AUTH-006":   "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/\n  Expected: no output",
	"AUTH-007":   "stat -c '%a %U:%G' /etc/passwd /etc/shadow /etc/group\n  Expected: 644 root:root, 640 root:shadow, 644 root:root",
	"AUTH-008":   "grep 'pam_wheel.so' /etc/pam.d/su\n  Expected: auth required pam_wheel.so use_uid (uncommented)",
	"PAM-001":    "grep -E 'minlen|minclass' /etc/security/pwquality.conf\n  Expected: minlen >= 14, minclass >= 4",
	"PAM-003":    "grep 'pam_faillock' /etc/pam.d/common-auth || grep 'pam_faillock' /etc/pam.d/system-auth\n  Expected: pam_faillock.so with deny= and unlock_time=",
	"PAM-005":    "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs\n  Expected: MAX=365, MIN=7, WARN=14",
	"NET-001":    "ufw status || firewall-cmd --state\n  Expected: active/running",
	"NET-003":    "sysctl net.ipv4.ip_forward\n  Expected: net.ipv4.ip_forward = 0",
	"NET-008":    "sysctl net.ipv6.conf.all.disable_ipv6\n  Expected: net.ipv6.conf.all.disable_ipv6 = 1",
	"SVC-001":    "dpkg -l telnet rsh-client 2>/dev/null || rpm -q telnet rsh 2>/dev/null\n  Expected: not installed",
	"SVC-002":    "sshd -T | grep -E 'ciphers|macs|kexalgorithms'\n  Expected: only strong algorithms",
	"SVC-007":    "systemctl is-active fail2ban || systemctl is-active crowdsec\n  Expected: active",
	"FS-001":     "find / -perm /6000 -type f 2>/dev/null | wc -l\n  Expected: only known system SUID/SGID files",
	"FS-002":     "find / -xdev -type f -perm -0002 2>/dev/null | wc -l\n  Expected: 0",
	"FS-003":     "find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | wc -l\n  Expected: 0",
	"FS-005":     "mount | grep /dev/shm\n  Expected: nodev,nosuid,noexec options present",
	"FS-006":     "ls -ld /home/*/\n  Expected: drwxr-x--- (750) or more restrictive",
	"FS-007":     "find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | wc -l\n  Expected: 0",
	"LOG-001":    "systemctl is-active rsyslog || systemctl is-active syslog-ng\n  Expected: active",
	"LOG-002":    "systemctl is-active auditd\n  Expected: active",
	"LOG-003":    "auditctl -l | head -5\n  Expected: rules for identity, actions, exec",
	"LOG-004":    "ls /etc/logrotate.conf /etc/logrotate.d/\n  Expected: config files present",
	"LOG-006":    "aide --check 2>&1 | head -1\n  Expected: AIDE found no differences or initialized DB",
	"PKG-001":    "apt list --upgradable 2>/dev/null || yum check-update 2>/dev/null\n  Expected: no security updates pending",
	"PKG-004":    "systemctl is-active unattended-upgrades || systemctl is-active dnf-automatic.timer\n  Expected: active",
	"HARD-003":   "sysctl kernel.randomize_va_space\n  Expected: kernel.randomize_va_space = 2",
	"HARD-004":   "sysctl kernel.dmesg_restrict\n  Expected: kernel.dmesg_restrict = 1",
	"HARD-005":   "sysctl kernel.yama.ptrace_scope\n  Expected: kernel.yama.ptrace_scope = 1",
	"HARD-009":   "lsmod | grep usb_storage\n  Expected: no output",
	"BOOT-001":   "grep -c 'password_pbkdf2' /etc/grub.d/40_custom\n  Expected: 1 or more",
	"BOOT-002":   "stat -c '%a %U:%G' /boot/grub/grub.cfg\n  Expected: 600 root:root",
	"BOOT-004":   "passwd -S root | awk '{print $2}'\n  Expected: P (password set)",
	"BOOT-005":   "dpkg -l apparmor 2>/dev/null || rpm -q selinux-policy 2>/dev/null\n  Expected: installed",
	"BOOT-006":   "getenforce 2>/dev/null || aa-status --enabled 2>/dev/null\n  Expected: Enforcing / Yes",
	"CRON-002":   "stat -c '%a %U:%G' /etc/crontab\n  Expected: 600 root:root",
	"CRON-004":   "ls -la /etc/cron.allow\n  Expected: file exists with 640 permissions",
	"CRYPTO-004": "openssl s_client -connect localhost:443 -tls1 2>&1 | grep -i 'protocol'\n  Expected: connection refused or error",
	"CRYPTO-007": "find /etc/ssl /etc/pki -name '*.key' -exec stat -c '%a %n' {} \\;\n  Expected: 600 for all private keys",
	"CRYPTO-009": "awk -F: '$2 !~ /^[$!*]/ && $2 !~ /^\\$6\\$|^\\$y\\$/ {print $1}' /etc/shadow\n  Expected: no output (all use SHA-512 or yescrypt)",
	"CTR-003":    "stat -c '%a %U:%G' /var/run/docker.sock\n  Expected: 660 root:docker",
	"CTR-004":    "docker ps -q | xargs -I{} docker inspect --format '{{.Config.User}}' {}\n  Expected: non-empty, non-root user",
	"CTR-005":    "docker ps -q | xargs -I{} docker inspect --format '{{.HostConfig.Privileged}}' {}\n  Expected: false for all",
	"CTR-006":    "docker ps -q | xargs -I{} docker inspect --format '{{.HostConfig.Memory}} {{.HostConfig.NanoCpus}}' {}\n  Expected: non-zero values",
}

// fixRisk indicates how risky the remediation itself is.
var fixRisk = map[string]string{
	"AUTH-001":   "LOW — only changes SSH config; ensure you have key-based access before applying",
	"AUTH-002":   "HIGH — if you don't have SSH keys configured, you will be locked out",
	"AUTH-003":   "HIGH — changing UID of active accounts can break running processes and file ownership",
	"AUTH-004":   "LOW — locking empty-password accounts has no impact on key-based access",
	"AUTH-005":   "LOW — system accounts should never need interactive login",
	"AUTH-006":   "MEDIUM — users will need to enter password for sudo; verify no automation depends on NOPASSWD",
	"AUTH-007":   "LOW — restores standard permissions, no service restart needed",
	"AUTH-008":   "MEDIUM — ensure trusted users are in the wheel group before applying",
	"PAM-001":    "LOW — only affects new password changes, not existing passwords",
	"PAM-003":    "MEDIUM — legitimate users can get locked out after failed attempts",
	"PAM-005":    "LOW — only affects future password expiration, existing sessions unaffected",
	"NET-001":    "HIGH — enabling a firewall with no rules can block all traffic; configure rules first",
	"NET-003":    "LOW — only affects packet forwarding, not normal server traffic",
	"NET-008":    "MEDIUM — disabling IPv6 can break services that depend on it",
	"SVC-001":    "LOW — removing unused legacy services has no impact on modern systems",
	"SVC-002":    "MEDIUM — old SSH clients may not support strong ciphers; test connectivity after applying",
	"SVC-007":    "LOW — fail2ban only blocks IPs after failed auth attempts",
	"FS-001":     "MEDIUM — removing SUID from system binaries (sudo, ping) can break functionality",
	"FS-002":     "LOW — only removes world-write bit, owner can still modify",
	"FS-003":     "LOW — sticky bit only prevents cross-user deletion in shared directories",
	"FS-005":     "LOW — remounts /dev/shm with restrictions, no data loss",
	"FS-006":     "LOW — tightens home directory access to owner only",
	"FS-007":     "LOW — assigns root ownership to orphaned files",
	"FS-008":     "HIGH — requires disk repartitioning; plan during provisioning, not on running systems",
	"LOG-001":    "LOW — installing a logging service has no negative side effects",
	"LOG-002":    "LOW — auditd only records events, does not block them",
	"LOG-003":    "LOW — adds audit logging rules, does not restrict operations",
	"LOG-004":    "LOW — logrotate only manages log file sizes",
	"LOG-006":    "LOW — AIDE only monitors file integrity, does not block changes",
	"PKG-001":    "MEDIUM — package updates can occasionally introduce regressions; test in staging first",
	"PKG-004":    "MEDIUM — automatic updates may restart services; schedule during maintenance windows",
	"HARD-003":   "LOW — ASLR is a kernel feature with no user-visible impact",
	"HARD-004":   "LOW — restricts dmesg to root only",
	"HARD-005":   "LOW — restricts ptrace to parent processes; may affect debuggers like strace/gdb",
	"HARD-009":   "LOW — only blocks USB storage; USB keyboards and mice still work",
	"BOOT-001":   "MEDIUM — if you forget the GRUB password, you cannot modify boot parameters without reinstalling",
	"BOOT-002":   "LOW — only changes file permissions, no service restart needed",
	"BOOT-004":   "LOW — setting root password only adds authentication for rescue mode",
	"BOOT-005":   "MEDIUM — MAC systems can block legitimate processes if profiles are too restrictive",
	"BOOT-006":   "HIGH — enforcing SELinux/AppArmor on a system not configured for it can block critical services",
	"CRON-002":   "LOW — only changes file permissions",
	"CRON-004":   "MEDIUM — users not in cron.allow lose ability to schedule cron jobs",
	"CRYPTO-004": "MEDIUM — clients that only support TLS 1.0/1.1 will be unable to connect",
	"CRYPTO-007": "LOW — only changes file permissions on private keys",
	"CRYPTO-009": "LOW — forces password rehash on next login, transparent to users",
	"CTR-003":    "LOW — only changes socket permissions",
	"CTR-004":    "MEDIUM — some containers may require root; test each container individually",
	"CTR-005":    "MEDIUM — containers may need specific capabilities; test with --cap-add instead",
	"CTR-006":    "LOW — adds resource limits that prevent resource exhaustion",
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
		if len(r.Details) > 0 {
			fmt.Printf("\n  %sDetails:%s\n", bold, rst)
			for k, v := range r.Details {
				fmt.Printf("    %s%s:%s %s\n", dim, k, rst, v)
			}
		}
		fmt.Println()
	}

	// Remediation steps (always shown)
	if steps, ok := remediationSteps[id]; ok {
		fmt.Printf("  %sRemediation:%s\n", bold, rst)
		for _, step := range steps {
			if strings.HasPrefix(step, "#") {
				fmt.Printf("    %s%s%s\n", dim, step, rst)
			} else {
				fmt.Printf("    %s%s%s\n", cyan, step, rst)
			}
		}
		fmt.Println()
	}

	// Verify fix
	if verify, ok := verifyFix[id]; ok {
		fmt.Printf("  %sVerify fix:%s\n", bold, rst)
		for _, line := range strings.Split(verify, "\n") {
			if strings.HasPrefix(line, "  Expected:") {
				fmt.Printf("    %s%s%s\n", dim, line, rst)
			} else {
				fmt.Printf("    %s%s%s\n", green, line, rst)
			}
		}
		fmt.Println()
	}

	// Risk level
	if risk, ok := fixRisk[id]; ok {
		fmt.Printf("  %sRemediation risk:%s ", bold, rst)
		riskLevel := strings.SplitN(risk, " — ", 2)
		switch riskLevel[0] {
		case "LOW":
			fmt.Printf("%s%s%s", green, riskLevel[0], rst)
		case "MEDIUM":
			fmt.Printf("%s%s%s", yellow, riskLevel[0], rst)
		case "HIGH":
			fmt.Printf("%s%s%s", red+bold, riskLevel[0], rst)
		}
		if len(riskLevel) > 1 {
			fmt.Printf(" — %s", riskLevel[1])
		}
		fmt.Println()
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
