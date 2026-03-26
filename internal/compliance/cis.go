package compliance

// CISLevel indicates which CIS Benchmark level a control belongs to.
type CISLevel int

const (
	L1 CISLevel = 1
	L2 CISLevel = 2
)

// CISControl maps an infraudit check to a CIS Benchmark control.
type CISControl struct {
	CheckID     string
	Section     string // CIS section number (e.g. "1.4.1")
	SectionName string // CIS section title
	Category    string // CIS category (e.g. "1. Initial Setup")
	Level       CISLevel
}

// CISCategory represents a CIS top-level section.
type CISCategory struct {
	Number string
	Name   string
}

// CISCategories defines the CIS Benchmark top-level sections.
var CISCategories = []CISCategory{
	{"1", "Initial Setup"},
	{"2", "Services"},
	{"3", "Network Configuration"},
	{"4", "Logging and Auditing"},
	{"5", "Access, Authentication and Authorization"},
	{"6", "System Maintenance"},
}

// CISControls maps all infraudit checks to CIS Benchmark controls.
// Based on CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 / CIS RHEL 9 Benchmark v2.0.0.
var CISControls = []CISControl{
	// ═══════════════════════════════════════════════════════
	// 1. Initial Setup
	// ═══════════════════════════════════════════════════════

	// 1.1 Filesystem Configuration
	{CheckID: "FS-008", Section: "1.1.2", SectionName: "Ensure separate partitions for /tmp, /var, /var/log, /home", Category: "1. Initial Setup", Level: L2},
	{CheckID: "FS-004", Section: "1.1.3", SectionName: "Ensure nodev, nosuid, noexec on /tmp", Category: "1. Initial Setup", Level: L1},
	{CheckID: "FS-009", Section: "1.1.4", SectionName: "Ensure /tmp is a separate partition or tmpfs", Category: "1. Initial Setup", Level: L1},
	{CheckID: "FS-010", Section: "1.1.5", SectionName: "Ensure /var/tmp has nodev, nosuid, noexec", Category: "1. Initial Setup", Level: L1},
	{CheckID: "FS-005", Section: "1.1.6", SectionName: "Ensure nodev, nosuid, noexec on /dev/shm", Category: "1. Initial Setup", Level: L1},
	{CheckID: "FS-011", Section: "1.1.7", SectionName: "Ensure systemd tmp.mount is enabled", Category: "1. Initial Setup", Level: L1},
	{CheckID: "FS-012", Section: "1.1.8", SectionName: "Ensure temporary file cleanup is configured", Category: "1. Initial Setup", Level: L1},
	{CheckID: "FS-003", Section: "1.1.21", SectionName: "Ensure sticky bit on world-writable directories", Category: "1. Initial Setup", Level: L1},

	// 1.1.1 Disable unused filesystems
	{CheckID: "HARD-008", Section: "1.1.1.1", SectionName: "Ensure mounting of uncommon filesystems is disabled", Category: "1. Initial Setup", Level: L1},
	{CheckID: "HARD-009", Section: "1.1.1.8", SectionName: "Ensure USB storage is disabled", Category: "1. Initial Setup", Level: L1},

	// 1.3 Filesystem Integrity
	{CheckID: "LOG-006", Section: "1.3.1", SectionName: "Ensure AIDE is installed", Category: "1. Initial Setup", Level: L1},
	{CheckID: "LOG-007", Section: "1.3.2", SectionName: "Ensure AIDE database is initialized", Category: "1. Initial Setup", Level: L1},
	{CheckID: "LOG-008", Section: "1.3.3", SectionName: "Ensure AIDE integrity checks are scheduled", Category: "1. Initial Setup", Level: L1},
	{CheckID: "LOG-009", Section: "1.3.4", SectionName: "Ensure AIDE covers critical paths", Category: "1. Initial Setup", Level: L1},

	// 1.4 Secure Boot Settings
	{CheckID: "BOOT-001", Section: "1.4.1", SectionName: "Ensure bootloader password is set", Category: "1. Initial Setup", Level: L1},
	{CheckID: "BOOT-002", Section: "1.4.2", SectionName: "Ensure bootloader configuration permissions are set", Category: "1. Initial Setup", Level: L1},
	{CheckID: "BOOT-003", Section: "1.4.3", SectionName: "Ensure UEFI Secure Boot is enabled", Category: "1. Initial Setup", Level: L2},
	{CheckID: "BOOT-004", Section: "1.4.4", SectionName: "Ensure authentication for single-user mode", Category: "1. Initial Setup", Level: L1},

	// 1.5 Additional Process Hardening
	{CheckID: "HARD-003", Section: "1.5.1", SectionName: "Ensure ASLR is enabled", Category: "1. Initial Setup", Level: L1},
	{CheckID: "HARD-004", Section: "1.5.2", SectionName: "Ensure dmesg access is restricted", Category: "1. Initial Setup", Level: L1},
	{CheckID: "HARD-005", Section: "1.5.3", SectionName: "Ensure ptrace is restricted", Category: "1. Initial Setup", Level: L1},
	{CheckID: "HARD-002", Section: "1.5.4", SectionName: "Ensure core dumps are disabled", Category: "1. Initial Setup", Level: L1},

	// 1.6 Mandatory Access Control
	{CheckID: "BOOT-005", Section: "1.6.1", SectionName: "Ensure SELinux or AppArmor is installed", Category: "1. Initial Setup", Level: L1},
	{CheckID: "BOOT-006", Section: "1.6.2", SectionName: "Ensure SELinux/AppArmor is enforcing", Category: "1. Initial Setup", Level: L1},
	{CheckID: "BOOT-007", Section: "1.6.3", SectionName: "Ensure no unconfined processes", Category: "1. Initial Setup", Level: L2},
	{CheckID: "BOOT-008", Section: "1.6.4", SectionName: "Ensure no MAC denials in logs", Category: "1. Initial Setup", Level: L2},

	// 1.7 Warning Banners
	{CheckID: "HARD-001", Section: "1.7.1", SectionName: "Ensure login banner is configured", Category: "1. Initial Setup", Level: L1},

	// 1.8 Crypto Policy
	{CheckID: "CRYPTO-001", Section: "1.8.1", SectionName: "Ensure system-wide crypto policy is not LEGACY", Category: "1. Initial Setup", Level: L1},
	{CheckID: "CRYPTO-002", Section: "1.8.2", SectionName: "Ensure certificates are not expired", Category: "1. Initial Setup", Level: L1},
	{CheckID: "CRYPTO-004", Section: "1.8.3", SectionName: "Ensure TLS 1.0 and 1.1 are disabled", Category: "1. Initial Setup", Level: L1},
	{CheckID: "CRYPTO-005", Section: "1.8.4", SectionName: "Ensure no weak cipher suites", Category: "1. Initial Setup", Level: L1},
	{CheckID: "CRYPTO-007", Section: "1.8.5", SectionName: "Ensure private key file permissions are restricted", Category: "1. Initial Setup", Level: L1},

	// 1.9 Updates
	{CheckID: "PKG-001", Section: "1.9.1", SectionName: "Ensure updates and patches are installed", Category: "1. Initial Setup", Level: L1},
	{CheckID: "PKG-004", Section: "1.9.2", SectionName: "Ensure automatic security updates are enabled", Category: "1. Initial Setup", Level: L1},

	// ═══════════════════════════════════════════════════════
	// 2. Services
	// ═══════════════════════════════════════════════════════

	// 2.1 Special Purpose Services
	{CheckID: "SVC-001", Section: "2.1.1", SectionName: "Ensure insecure services are not installed", Category: "2. Services", Level: L1},
	{CheckID: "SVC-003", Section: "2.1.2", SectionName: "Ensure NTP is configured and synchronized", Category: "2. Services", Level: L1},
	{CheckID: "SVC-004", Section: "2.1.3", SectionName: "Ensure NTP daemon is not running as root", Category: "2. Services", Level: L1},
	{CheckID: "SVC-012", Section: "2.1.4", SectionName: "Ensure X Window System is not installed", Category: "2. Services", Level: L1},
	{CheckID: "SVC-013", Section: "2.1.5", SectionName: "Ensure autofs (automount) is disabled", Category: "2. Services", Level: L1},

	// 2.2 Service Clients
	{CheckID: "SVC-007", Section: "2.2.1", SectionName: "Ensure intrusion detection is active", Category: "2. Services", Level: L2},
	{CheckID: "SVC-009", Section: "2.2.2", SectionName: "Ensure MTA is configured as local-only", Category: "2. Services", Level: L1},
	{CheckID: "SVC-010", Section: "2.2.3", SectionName: "Ensure MTA is not an open relay", Category: "2. Services", Level: L1},
	{CheckID: "SVC-011", Section: "2.2.4", SectionName: "Ensure root mail is forwarded to a monitored account", Category: "2. Services", Level: L1},

	// 2.3 NFS/RPC
	{CheckID: "NFS-001", Section: "2.3.1", SectionName: "Ensure NFS exports are properly configured", Category: "2. Services", Level: L1},
	{CheckID: "NFS-002", Section: "2.3.2", SectionName: "Ensure NFSv3 is disabled if NFSv4 is available", Category: "2. Services", Level: L1},
	{CheckID: "NFS-003", Section: "2.3.3", SectionName: "Ensure Samba config is reviewed", Category: "2. Services", Level: L1},
	{CheckID: "NFS-004", Section: "2.3.4", SectionName: "Ensure rpcbind is disabled if NFS not in use", Category: "2. Services", Level: L1},

	// ═══════════════════════════════════════════════════════
	// 3. Network Configuration
	// ═══════════════════════════════════════════════════════

	// 3.1 Network Parameters
	{CheckID: "NET-003", Section: "3.1.1", SectionName: "Ensure IP forwarding is disabled", Category: "3. Network Configuration", Level: L1},
	{CheckID: "NET-008", Section: "3.1.2", SectionName: "Ensure IPv6 is disabled or properly configured", Category: "3. Network Configuration", Level: L1},

	// 3.2 Host Network Parameters
	{CheckID: "NET-004", Section: "3.2.1", SectionName: "Ensure services bind to specific addresses", Category: "3. Network Configuration", Level: L1},

	// 3.3 SNMP
	{CheckID: "NET-009", Section: "3.3.1", SectionName: "Ensure SNMP v1/v2c is disabled", Category: "3. Network Configuration", Level: L1},
	{CheckID: "NET-010", Section: "3.3.2", SectionName: "Ensure default SNMP community strings are removed", Category: "3. Network Configuration", Level: L1},
	{CheckID: "NET-011", Section: "3.3.3", SectionName: "Ensure SNMP is removed if unused", Category: "3. Network Configuration", Level: L1},

	// 3.4 DNS
	{CheckID: "NET-005", Section: "3.4.1", SectionName: "Ensure DNS resolvers are configured", Category: "3. Network Configuration", Level: L1},
	{CheckID: "NET-006", Section: "3.4.2", SectionName: "Ensure DNSSEC validation is enabled", Category: "3. Network Configuration", Level: L2},
	{CheckID: "NET-007", Section: "3.4.3", SectionName: "Ensure DNS over TLS/HTTPS is configured", Category: "3. Network Configuration", Level: L2},

	// 3.5 Firewall
	{CheckID: "NET-001", Section: "3.5.1", SectionName: "Ensure a firewall is installed and active", Category: "3. Network Configuration", Level: L1},
	{CheckID: "NET-002", Section: "3.5.2", SectionName: "Ensure unnecessary open ports are not listening", Category: "3. Network Configuration", Level: L1},

	// ═══════════════════════════════════════════════════════
	// 4. Logging and Auditing
	// ═══════════════════════════════════════════════════════

	// 4.1 Configure System Accounting (auditd)
	{CheckID: "LOG-002", Section: "4.1.1", SectionName: "Ensure auditd is installed and running", Category: "4. Logging and Auditing", Level: L2},
	{CheckID: "LOG-003", Section: "4.1.2", SectionName: "Ensure audit rules for sensitive operations", Category: "4. Logging and Auditing", Level: L2},

	// 4.2 Configure Logging
	{CheckID: "LOG-001", Section: "4.2.1", SectionName: "Ensure rsyslog/syslog-ng is installed and running", Category: "4. Logging and Auditing", Level: L1},
	{CheckID: "LOG-005", Section: "4.2.2", SectionName: "Ensure log files are not world-readable", Category: "4. Logging and Auditing", Level: L1},
	{CheckID: "LOG-004", Section: "4.2.3", SectionName: "Ensure logrotate is configured", Category: "4. Logging and Auditing", Level: L1},

	// ═══════════════════════════════════════════════════════
	// 5. Access, Authentication and Authorization
	// ═══════════════════════════════════════════════════════

	// 5.1 Cron
	{CheckID: "CRON-001", Section: "5.1.1", SectionName: "Ensure cron daemon is enabled", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "CRON-002", Section: "5.1.2", SectionName: "Ensure permissions on /etc/crontab", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "CRON-003", Section: "5.1.3", SectionName: "Ensure permissions on cron directories", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "CRON-004", Section: "5.1.4", SectionName: "Ensure cron access is restricted via cron.allow", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "CRON-005", Section: "5.1.5", SectionName: "Ensure at access is restricted via at.allow", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "CRON-006", Section: "5.1.6", SectionName: "Ensure no suspicious cron jobs", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "CRON-007", Section: "5.1.7", SectionName: "Ensure user crontabs are reviewed", Category: "5. Access, Authentication and Authorization", Level: L2},

	// 5.2 SSH Server Configuration
	{CheckID: "AUTH-001", Section: "5.2.1", SectionName: "Ensure SSH root login is disabled", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "AUTH-002", Section: "5.2.2", SectionName: "Ensure SSH PasswordAuthentication is disabled", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "SVC-002", Section: "5.2.3", SectionName: "Ensure SSH ciphers, MACs and timeouts are configured", Category: "5. Access, Authentication and Authorization", Level: L1},

	// 5.3 PAM
	{CheckID: "AUTH-006", Section: "5.3.1", SectionName: "Ensure NOPASSWD is not used in sudoers", Category: "5. Access, Authentication and Authorization", Level: L1},

	// 5.4 Password Quality
	{CheckID: "PAM-001", Section: "5.4.1", SectionName: "Ensure password creation requirements are configured", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "PAM-003", Section: "5.4.2", SectionName: "Ensure lockout for failed password attempts", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "PAM-002", Section: "5.4.3", SectionName: "Ensure password reuse is limited", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "PAM-004", Section: "5.4.4", SectionName: "Ensure pam_faillock precedes pam_unix", Category: "5. Access, Authentication and Authorization", Level: L1},

	// 5.5 Password Settings
	{CheckID: "PAM-005", Section: "5.5.1", SectionName: "Ensure password expiration policies are set", Category: "5. Access, Authentication and Authorization", Level: L1},

	// 5.6 User Accounts
	{CheckID: "AUTH-005", Section: "5.6.1", SectionName: "Ensure system accounts are secured", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "AUTH-008", Section: "5.6.2", SectionName: "Ensure su command access is restricted", Category: "5. Access, Authentication and Authorization", Level: L1},
	{CheckID: "SVC-008", Section: "5.6.3", SectionName: "Ensure processes running as root are reviewed", Category: "5. Access, Authentication and Authorization", Level: L1},

	// ═══════════════════════════════════════════════════════
	// 6. System Maintenance
	// ═══════════════════════════════════════════════════════

	// 6.1 File Permissions
	{CheckID: "AUTH-004", Section: "6.1.1", SectionName: "Ensure accounts use shadowed passwords", Category: "6. System Maintenance", Level: L1},
	{CheckID: "AUTH-007", Section: "6.1.2", SectionName: "Ensure permissions on /etc/passwd, shadow, group", Category: "6. System Maintenance", Level: L1},
	{CheckID: "FS-002", Section: "6.1.3", SectionName: "Ensure no world-writable files exist", Category: "6. System Maintenance", Level: L1},
	{CheckID: "FS-007", Section: "6.1.4", SectionName: "Ensure no unowned or ungrouped files exist", Category: "6. System Maintenance", Level: L1},
	{CheckID: "FS-001", Section: "6.1.5", SectionName: "Ensure SUID/SGID executables are audited", Category: "6. System Maintenance", Level: L1},

	// 6.2 User and Group Settings
	{CheckID: "AUTH-003", Section: "6.2.1", SectionName: "Ensure root is the only UID 0 account", Category: "6. System Maintenance", Level: L1},
	{CheckID: "FS-006", Section: "6.2.2", SectionName: "Ensure home directory permissions are 750 or more restrictive", Category: "6. System Maintenance", Level: L1},

	// 6.3 Crypto
	{CheckID: "CRYPTO-009", Section: "6.3.1", SectionName: "Ensure no MD5/SHA1 password hashes", Category: "6. System Maintenance", Level: L1},
}

// ControlsByLevel returns controls filtered by CIS level.
func ControlsByLevel(level CISLevel) []CISControl {
	var result []CISControl
	for _, c := range CISControls {
		if c.Level <= level {
			result = append(result, c)
		}
	}
	return result
}

// ControlByCheckID returns the CIS control for a check ID, or nil.
func ControlByCheckID(checkID string) *CISControl {
	for i := range CISControls {
		if CISControls[i].CheckID == checkID {
			return &CISControls[i]
		}
	}
	return nil
}
