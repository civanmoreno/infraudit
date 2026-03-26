package pam

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&pwquality{})
}

type pwquality struct{}

func (c *pwquality) ID() string               { return "PAM-001" }
func (c *pwquality) Name() string             { return "Password quality enforced via pam_pwquality" }
func (c *pwquality) Category() string         { return "pam" }
func (c *pwquality) Severity() check.Severity { return check.Medium }
func (c *pwquality) Description() string {
	return "Verify pam_pwquality is configured with adequate password complexity requirements"
}

func (c *pwquality) Run() check.Result {
	// Check if pam_pwquality is enabled in PAM
	pamEnabled := pamModuleEnabled("pam_pwquality.so")
	if !pamEnabled {
		return check.Result{
			Status:      check.Fail,
			Message:     "pam_pwquality is not enabled in PAM configuration",
			Remediation: "Install libpam-pwquality and add 'password requisite pam_pwquality.so' to PAM config",
		}
	}

	// Read /etc/security/pwquality.conf
	conf, err := parsePwqualityConf()
	if err != nil {
		return check.Result{
			Status:      check.Warn,
			Message:     "pam_pwquality enabled but could not read pwquality.conf: " + err.Error(),
			Remediation: "Create /etc/security/pwquality.conf with minlen=14, minclass=4",
		}
	}

	var issues []string

	minlen, ok := conf["minlen"]
	if !ok || atoi(minlen) < 14 {
		issues = append(issues, fmt.Sprintf("minlen=%s (recommended >= 14)", minlen))
	}

	minclass, ok := conf["minclass"]
	if !ok || atoi(minclass) < 4 {
		issues = append(issues, fmt.Sprintf("minclass=%s (recommended >= 4)", minclass))
	}

	if len(issues) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "pam_pwquality enabled but weak settings: " + strings.Join(issues, ", "),
			Remediation: "Set minlen=14, minclass=4 in /etc/security/pwquality.conf",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "pam_pwquality is configured with adequate complexity requirements",
	}
}

func parsePwqualityConf() (map[string]string, error) {
	f, err := os.Open(check.P("/etc/security/pwquality.conf"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	conf := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			conf[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return conf, scanner.Err()
}

// pamModuleEnabled checks if a PAM module is active in common password configs.
func pamModuleEnabled(module string) bool {
	paths := []string{
		"/etc/pam.d/common-password",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	}
	for _, path := range paths {
		if fileContainsActive(path, module) {
			return true
		}
	}
	return false
}

func fileContainsActive(path, substr string) bool {
	f, err := os.Open(check.P(path))
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
