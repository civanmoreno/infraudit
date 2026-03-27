package services

import (
	"fmt"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

type unwantedSvc struct {
	id       string
	name     string
	desc     string
	severity check.Severity
	pkgs     []string
	svcs     []string
}

func (c *unwantedSvc) ID() string               { return c.id }
func (c *unwantedSvc) Name() string             { return c.name }
func (c *unwantedSvc) Category() string         { return "services" }
func (c *unwantedSvc) Severity() check.Severity { return c.severity }
func (c *unwantedSvc) Description() string      { return c.desc }
func (c *unwantedSvc) RequiredInit() string     { return "systemd" }

func (c *unwantedSvc) Run() check.Result {
	var installed []string
	for _, pkg := range c.pkgs {
		if check.PkgInstalled(pkg) {
			installed = append(installed, pkg)
		}
	}

	var active []string
	for _, svc := range c.svcs {
		if check.ServiceActive(svc) {
			active = append(active, svc)
		}
	}

	if len(installed) == 0 && len(active) == 0 {
		return check.Result{
			Status:  check.Pass,
			Message: fmt.Sprintf("%s is not installed", c.name),
		}
	}

	var issues []string
	if len(installed) > 0 {
		issues = append(issues, "installed: "+strings.Join(installed, ", "))
	}
	if len(active) > 0 {
		issues = append(issues, "active: "+strings.Join(active, ", "))
	}

	return check.Result{
		Status:      check.Fail,
		Message:     fmt.Sprintf("%s found (%s)", c.name, strings.Join(issues, "; ")),
		Remediation: fmt.Sprintf("Remove with: apt purge %s / yum remove %s", strings.Join(c.pkgs, " "), strings.Join(c.pkgs, " ")),
	}
}

func init() {
	for _, s := range unwantedServices {
		check.Register(s)
	}
}

var unwantedServices = []*unwantedSvc{
	{
		id: "SVC-014", name: "Avahi daemon not installed",
		desc: "Ensure avahi-daemon service is not installed (mDNS/DNS-SD)", severity: check.Medium,
		pkgs: []string{"avahi-daemon", "avahi"}, svcs: []string{"avahi-daemon"},
	},
	{
		id: "SVC-015", name: "CUPS not installed on servers",
		desc: "Ensure CUPS print service is not installed on servers", severity: check.Medium,
		pkgs: []string{"cups", "cups-server"}, svcs: []string{"cups"},
	},
	{
		id: "SVC-016", name: "DHCP server not installed",
		desc: "Ensure DHCP server is not installed unless required", severity: check.Medium,
		pkgs: []string{"isc-dhcp-server", "dhcp-server"}, svcs: []string{"isc-dhcp-server", "dhcpd"},
	},
	{
		id: "SVC-017", name: "DNS server not installed",
		desc: "Ensure DNS server is not installed unless required", severity: check.Medium,
		pkgs: []string{"bind9", "bind"}, svcs: []string{"named", "bind9"},
	},
	{
		id: "SVC-018", name: "FTP server not installed",
		desc: "Ensure FTP server is not installed (use SFTP instead)", severity: check.High,
		pkgs: []string{"vsftpd", "proftpd-basic", "pure-ftpd"}, svcs: []string{"vsftpd", "proftpd", "pure-ftpd"},
	},
	{
		id: "SVC-019", name: "HTTP server not installed",
		desc: "Ensure HTTP server is not installed unless required", severity: check.Medium,
		pkgs: []string{"apache2", "httpd", "nginx"}, svcs: []string{"apache2", "httpd", "nginx"},
	},
	{
		id: "SVC-020", name: "IMAP/POP3 server not installed",
		desc: "Ensure IMAP and POP3 server is not installed", severity: check.Medium,
		pkgs: []string{"dovecot-imapd", "dovecot-pop3d", "cyrus-imapd"}, svcs: []string{"dovecot"},
	},
	{
		id: "SVC-021", name: "Samba server not installed",
		desc: "Ensure Samba is not installed unless required", severity: check.Medium,
		pkgs: []string{"samba"}, svcs: []string{"smbd", "nmbd"},
	},
	{
		id: "SVC-022", name: "Squid proxy not installed",
		desc: "Ensure HTTP proxy server is not installed unless required", severity: check.Medium,
		pkgs: []string{"squid"}, svcs: []string{"squid"},
	},
	{
		id: "SVC-023", name: "SNMP server not installed",
		desc: "Ensure SNMP server is not installed unless required", severity: check.Medium,
		pkgs: []string{"snmpd", "net-snmp"}, svcs: []string{"snmpd"},
	},
	{
		id: "SVC-024", name: "Telnet server not installed",
		desc: "Ensure telnet server is not installed", severity: check.Critical,
		pkgs: []string{"telnetd", "telnet-server", "inetutils-telnetd"}, svcs: []string{"telnetd", "telnet.socket"},
	},
	{
		id: "SVC-025", name: "rsync not installed or restricted",
		desc: "Ensure rsync service is not installed or restricted", severity: check.Medium,
		pkgs: []string{"rsync"}, svcs: []string{"rsync", "rsyncd"},
	},
	{
		id: "SVC-026", name: "NIS server not installed",
		desc: "Ensure NIS server is not installed", severity: check.High,
		pkgs: []string{"nis", "ypserv"}, svcs: []string{"ypserv"},
	},
	{
		id: "SVC-027", name: "NIS client not installed",
		desc: "Ensure NIS client is not installed", severity: check.Medium,
		pkgs: []string{"nis", "yp-tools", "ypbind"}, svcs: []string{"ypbind"},
	},
}
