package services

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&insecureServices{})
}

type insecureServices struct{}

func (c *insecureServices) ID() string             { return "SVC-001" }
func (c *insecureServices) Name() string           { return "No insecure services running" }
func (c *insecureServices) Category() string       { return "services" }
func (c *insecureServices) Severity() check.Severity { return check.Critical }
func (c *insecureServices) Description() string    { return "Verify insecure services like telnet, rsh, rlogin, xinetd are not running" }

var insecureSvcs = []string{
	"telnet.socket", "telnetd", "rsh.socket", "rlogin.socket",
	"rexec.socket", "xinetd", "tftp.socket", "vsftpd",
}

func (c *insecureServices) Run() check.Result {
	var active []string
	for _, svc := range insecureSvcs {
		out, err := exec.Command("systemctl", "is-active", svc).CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			active = append(active, svc)
		}
	}

	if len(active) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("Insecure services running: %s", strings.Join(active, ", ")),
			Remediation: "Stop and disable: systemctl disable --now <service>",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No insecure services detected",
	}
}
