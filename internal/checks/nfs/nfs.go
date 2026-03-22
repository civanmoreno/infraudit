package nfs

import (
	"bufio"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&nfsExports{})
	check.Register(&nfsv3Disabled{})
	check.Register(&sambaConfig{})
	check.Register(&rpcbindDisabled{})
}

// NFS-001
type nfsExports struct{}

func (c *nfsExports) ID() string             { return "NFS-001" }
func (c *nfsExports) Name() string           { return "NFS exports reviewed" }
func (c *nfsExports) Category() string       { return "nfs" }
func (c *nfsExports) Severity() check.Severity { return check.High }
func (c *nfsExports) Description() string    { return "Verify NFS exports are not world-exported and use root_squash" }

func (c *nfsExports) Run() check.Result {
	f, err := os.Open("/etc/exports")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "NFS exports not configured"}
	}
	defer f.Close()

	var issues []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "*") || strings.Contains(line, "0.0.0.0/0") {
			issues = append(issues, "world-exported share found")
		}
		if strings.Contains(line, "no_root_squash") {
			issues = append(issues, "no_root_squash found")
		}
	}

	if len(issues) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "NFS export issues: " + strings.Join(issues, "; "),
			Remediation: "Restrict NFS exports to specific hosts and ensure root_squash is enabled",
		}
	}
	return check.Result{Status: check.Pass, Message: "NFS exports are properly configured"}
}

// NFS-002
type nfsv3Disabled struct{}

func (c *nfsv3Disabled) ID() string             { return "NFS-002" }
func (c *nfsv3Disabled) Name() string           { return "NFSv3 disabled if NFSv4 available" }
func (c *nfsv3Disabled) Category() string       { return "nfs" }
func (c *nfsv3Disabled) Severity() check.Severity { return check.Medium }
func (c *nfsv3Disabled) Description() string    { return "Verify NFSv3 is disabled in favor of NFSv4" }

func (c *nfsv3Disabled) Run() check.Result {
	// Check if NFS server is running
	out, err := check.RunCmd(check.DefaultCmdTimeout, "systemctl", "is-active", "nfs-server")
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return check.Result{Status: check.Pass, Message: "NFS server not running"}
	}

	// Check nfs.conf or sysconfig
	data, err := os.ReadFile("/etc/nfs.conf")
	if err == nil {
		if strings.Contains(string(data), "vers3=no") || strings.Contains(string(data), "vers3=0") {
			return check.Result{Status: check.Pass, Message: "NFSv3 is disabled"}
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "NFSv3 may be enabled",
		Remediation: "Set vers3=no in /etc/nfs.conf",
	}
}

// NFS-003
type sambaConfig struct{}

func (c *sambaConfig) ID() string             { return "NFS-003" }
func (c *sambaConfig) Name() string           { return "Samba config reviewed" }
func (c *sambaConfig) Category() string       { return "nfs" }
func (c *sambaConfig) Severity() check.Severity { return check.Medium }
func (c *sambaConfig) Description() string    { return "Verify Samba does not allow guest access" }

func (c *sambaConfig) Run() check.Result {
	f, err := os.Open("/etc/samba/smb.conf")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "Samba not configured"}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "guest ok") && strings.Contains(line, "yes") {
			return check.Result{
				Status:      check.Warn,
				Message:     "Samba allows guest access",
				Remediation: "Set 'guest ok = no' in /etc/samba/smb.conf",
			}
		}
		if strings.Contains(line, "map to guest") {
			return check.Result{
				Status:  check.Warn,
				Message: "Samba maps failed logins to guest",
			}
		}
	}
	return check.Result{Status: check.Pass, Message: "Samba guest access is disabled"}
}

// NFS-004
type rpcbindDisabled struct{}

func (c *rpcbindDisabled) ID() string             { return "NFS-004" }
func (c *rpcbindDisabled) Name() string           { return "rpcbind disabled if NFS not in use" }
func (c *rpcbindDisabled) Category() string       { return "nfs" }
func (c *rpcbindDisabled) Severity() check.Severity { return check.Medium }
func (c *rpcbindDisabled) Description() string    { return "Verify rpcbind is not running if NFS is not needed" }

func (c *rpcbindDisabled) Run() check.Result {
	rpcOut, _ := check.RunCmd(check.DefaultCmdTimeout, "systemctl", "is-active", "rpcbind")
	rpcActive := strings.TrimSpace(string(rpcOut)) == "active"

	nfsOut, _ := check.RunCmd(check.DefaultCmdTimeout, "systemctl", "is-active", "nfs-server")
	nfsActive := strings.TrimSpace(string(nfsOut)) == "active"

	if rpcActive && !nfsActive {
		return check.Result{
			Status:      check.Warn,
			Message:     "rpcbind is running but NFS server is not active",
			Remediation: "Disable rpcbind if not needed: 'systemctl disable --now rpcbind'",
		}
	}
	if rpcActive && nfsActive {
		return check.Result{Status: check.Pass, Message: "rpcbind is running (required by NFS)"}
	}
	return check.Result{Status: check.Pass, Message: "rpcbind is not running"}
}
