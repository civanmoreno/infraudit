package pam

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&pwhistory{})
}

type pwhistory struct{}

func (c *pwhistory) ID() string             { return "PAM-002" }
func (c *pwhistory) Name() string           { return "Password reuse prevention configured" }
func (c *pwhistory) Category() string       { return "pam" }
func (c *pwhistory) Severity() check.Severity { return check.Medium }
func (c *pwhistory) Description() string {
	return "Verify pam_pwhistory or pam_unix remember prevents password reuse (>= 5)"
}

func (c *pwhistory) Run() check.Result {
	paths := []string{
		"/etc/pam.d/common-password",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	}

	for _, path := range paths {
		remember := findRememberValue(path)
		if remember >= 5 {
			return check.Result{
				Status:  check.Pass,
				Message: "Password reuse prevention is configured (remember=" + strconv.Itoa(remember) + ")",
			}
		}
		if remember > 0 {
			return check.Result{
				Status:      check.Warn,
				Message:     "Password reuse prevention is weak (remember=" + strconv.Itoa(remember) + ", recommended >= 5)",
				Remediation: "Set 'remember=5' in pam_pwhistory.so or pam_unix.so in PAM config",
			}
		}
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "Password reuse prevention is not configured",
		Remediation: "Add 'password required pam_pwhistory.so remember=5' to PAM config",
	}
}

func findRememberValue(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if (strings.Contains(line, "pam_pwhistory.so") || strings.Contains(line, "pam_unix.so")) &&
			strings.Contains(line, "remember=") {
			for _, field := range strings.Fields(line) {
				if strings.HasPrefix(field, "remember=") {
					val, _ := strconv.Atoi(strings.TrimPrefix(field, "remember="))
					return val
				}
			}
		}
	}
	return -1
}
