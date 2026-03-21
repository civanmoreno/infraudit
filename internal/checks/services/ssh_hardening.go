package services

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&sshHardening{})
}

type sshHardening struct{}

func (c *sshHardening) ID() string             { return "SVC-002" }
func (c *sshHardening) Name() string           { return "SSH ciphers and timeouts hardened" }
func (c *sshHardening) Category() string       { return "services" }
func (c *sshHardening) Severity() check.Severity { return check.High }
func (c *sshHardening) Description() string    { return "Verify SSH uses strong ciphers, MACs, and has idle timeout configured" }

var weakCiphers = []string{"3des-cbc", "arcfour", "blowfish-cbc", "cast128-cbc"}
var weakMACs = []string{"hmac-md5", "hmac-sha1-96", "hmac-md5-96"}

func (c *sshHardening) Run() check.Result {
	conf := parseSSHConfig("/etc/ssh/sshd_config")

	var issues []string

	// Check ciphers
	if ciphers, ok := conf["ciphers"]; ok {
		for _, wc := range weakCiphers {
			if strings.Contains(strings.ToLower(ciphers), wc) {
				issues = append(issues, "weak cipher: "+wc)
			}
		}
	}

	// Check MACs
	if macs, ok := conf["macs"]; ok {
		for _, wm := range weakMACs {
			if strings.Contains(strings.ToLower(macs), wm) {
				issues = append(issues, "weak MAC: "+wm)
			}
		}
	}

	// Check ClientAliveInterval
	if val, ok := conf["clientaliveinterval"]; !ok || val == "0" {
		issues = append(issues, "ClientAliveInterval not set")
	}

	// Check ClientAliveCountMax
	if val, ok := conf["clientalivecountmax"]; !ok || val == "0" {
		issues = append(issues, "ClientAliveCountMax not set")
	}

	if len(issues) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("SSH hardening issues: %s", strings.Join(issues, "; ")),
			Remediation: "Configure strong Ciphers, MACs, and set ClientAliveInterval/ClientAliveCountMax in sshd_config",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "SSH ciphers, MACs, and timeouts are properly configured",
	}
}

func parseSSHConfig(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	conf := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			conf[strings.ToLower(parts[0])] = strings.Join(parts[1:], " ")
		}
	}
	return conf
}
