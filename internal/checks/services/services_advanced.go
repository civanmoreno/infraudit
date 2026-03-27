package services

import (
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&rpcbindDisabled{})
	check.Register(&xdmcpDisabled{})
	check.Register(&prelink{})
	check.Register(&apportDisabled{})
	check.Register(&tftpServer{})
	check.Register(&ldapServer{})
	check.Register(&ntalkServer{})
	check.Register(&rshServer{})
}

// SVC-049: rpcbind not running
type rpcbindDisabled struct{}

func (c *rpcbindDisabled) ID() string               { return "SVC-049" }
func (c *rpcbindDisabled) Name() string             { return "rpcbind service disabled" }
func (c *rpcbindDisabled) Category() string         { return "services" }
func (c *rpcbindDisabled) Severity() check.Severity { return check.Medium }
func (c *rpcbindDisabled) Description() string      { return "Ensure rpcbind is not installed or running" }
func (c *rpcbindDisabled) RequiredInit() string     { return "systemd" }

func (c *rpcbindDisabled) Run() check.Result {
	if check.ServiceActive("rpcbind") {
		return check.Result{Status: check.Fail, Message: "rpcbind is running", Remediation: "systemctl stop rpcbind && systemctl disable rpcbind"}
	}
	return check.Result{Status: check.Pass, Message: "rpcbind is not running"}
}

// SVC-050: XDMCP disabled
type xdmcpDisabled struct{}

func (c *xdmcpDisabled) ID() string               { return "SVC-050" }
func (c *xdmcpDisabled) Name() string             { return "XDMCP disabled" }
func (c *xdmcpDisabled) Category() string         { return "services" }
func (c *xdmcpDisabled) Severity() check.Severity { return check.Medium }
func (c *xdmcpDisabled) Description() string      { return "Ensure XDMCP is not enabled" }

func (c *xdmcpDisabled) Run() check.Result {
	data, err := os.ReadFile("/etc/gdm3/custom.conf")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "GDM not installed or no custom.conf (OK)"}
	}
	if strings.Contains(string(data), "Enable=true") {
		return check.Result{Status: check.Fail, Message: "XDMCP is enabled in GDM", Remediation: "Set Enable=false under [xdmcp] in /etc/gdm3/custom.conf"}
	}
	return check.Result{Status: check.Pass, Message: "XDMCP is not enabled"}
}

// SVC-051: prelink not installed
type prelink struct{}

func (c *prelink) ID() string               { return "SVC-051" }
func (c *prelink) Name() string             { return "prelink not installed" }
func (c *prelink) Category() string         { return "services" }
func (c *prelink) Severity() check.Severity { return check.Medium }
func (c *prelink) Description() string {
	return "Ensure prelink is not installed (interferes with AIDE)"
}

func (c *prelink) Run() check.Result {
	if check.PkgInstalled("prelink") {
		return check.Result{Status: check.Fail, Message: "prelink is installed", Remediation: "apt purge prelink / yum remove prelink"}
	}
	return check.Result{Status: check.Pass, Message: "prelink is not installed"}
}

// SVC-052: apport disabled
type apportDisabled struct{}

func (c *apportDisabled) ID() string               { return "SVC-052" }
func (c *apportDisabled) Name() string             { return "apport (crash reporter) disabled" }
func (c *apportDisabled) Category() string         { return "services" }
func (c *apportDisabled) Severity() check.Severity { return check.Low }
func (c *apportDisabled) Description() string {
	return "Ensure apport crash reporter is disabled on servers"
}
func (c *apportDisabled) SupportedOS() []string { return []string{"debian"} }
func (c *apportDisabled) RequiredInit() string  { return "systemd" }

func (c *apportDisabled) Run() check.Result {
	if !check.PkgInstalled("apport") {
		return check.Result{Status: check.Pass, Message: "apport is not installed"}
	}
	if check.ServiceActive("apport") {
		return check.Result{Status: check.Warn, Message: "apport is running", Remediation: "systemctl stop apport && systemctl disable apport"}
	}
	return check.Result{Status: check.Pass, Message: "apport is installed but not running"}
}

// SVC-053: tftp-server not installed
type tftpServer struct{}

func (c *tftpServer) ID() string               { return "SVC-053" }
func (c *tftpServer) Name() string             { return "TFTP server not installed" }
func (c *tftpServer) Category() string         { return "services" }
func (c *tftpServer) Severity() check.Severity { return check.High }
func (c *tftpServer) Description() string      { return "Ensure TFTP server is not installed" }

func (c *tftpServer) Run() check.Result {
	if check.PkgInstalled("tftpd-hpa", "tftp-server") {
		return check.Result{Status: check.Fail, Message: "TFTP server is installed", Remediation: "apt purge tftpd-hpa / yum remove tftp-server"}
	}
	return check.Result{Status: check.Pass, Message: "TFTP server is not installed"}
}

// SVC-054: LDAP server not installed
type ldapServer struct{}

func (c *ldapServer) ID() string               { return "SVC-054" }
func (c *ldapServer) Name() string             { return "LDAP server not installed" }
func (c *ldapServer) Category() string         { return "services" }
func (c *ldapServer) Severity() check.Severity { return check.Medium }
func (c *ldapServer) Description() string {
	return "Ensure LDAP server is not installed unless required"
}

func (c *ldapServer) Run() check.Result {
	if check.PkgInstalled("slapd", "openldap-servers") {
		return check.Result{Status: check.Fail, Message: "LDAP server is installed", Remediation: "apt purge slapd / yum remove openldap-servers"}
	}
	return check.Result{Status: check.Pass, Message: "LDAP server is not installed"}
}

// SVC-055: ntalk not installed
type ntalkServer struct{}

func (c *ntalkServer) ID() string               { return "SVC-055" }
func (c *ntalkServer) Name() string             { return "talk server not installed" }
func (c *ntalkServer) Category() string         { return "services" }
func (c *ntalkServer) Severity() check.Severity { return check.Medium }
func (c *ntalkServer) Description() string      { return "Ensure talk server is not installed" }

func (c *ntalkServer) Run() check.Result {
	if check.PkgInstalled("talk", "talkd", "inetutils-talkd") {
		return check.Result{Status: check.Fail, Message: "talk server is installed", Remediation: "apt purge talk / yum remove talk"}
	}
	return check.Result{Status: check.Pass, Message: "talk server is not installed"}
}

// SVC-056: rsh server not installed
type rshServer struct{}

func (c *rshServer) ID() string               { return "SVC-056" }
func (c *rshServer) Name() string             { return "rsh server not installed" }
func (c *rshServer) Category() string         { return "services" }
func (c *rshServer) Severity() check.Severity { return check.Critical }
func (c *rshServer) Description() string      { return "Ensure rsh server is not installed" }

func (c *rshServer) Run() check.Result {
	if check.PkgInstalled("rsh-server", "rsh") {
		return check.Result{Status: check.Fail, Message: "rsh server is installed", Remediation: "apt purge rsh-server / yum remove rsh-server"}
	}
	return check.Result{Status: check.Pass, Message: "rsh server is not installed"}
}
