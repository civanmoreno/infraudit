package pam

import (
	"bufio"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&pamOrder{})
}

type pamOrder struct{}

func (c *pamOrder) ID() string               { return "PAM-004" }
func (c *pamOrder) Name() string             { return "PAM module ordering correct" }
func (c *pamOrder) Category() string         { return "pam" }
func (c *pamOrder) Severity() check.Severity { return check.Medium }
func (c *pamOrder) Description() string {
	return "Verify pam_faillock appears before pam_unix in auth stack"
}

func (c *pamOrder) Run() check.Result {
	paths := []string{
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	}

	for _, path := range paths {
		result := checkOrder(path)
		if result != nil {
			return *result
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "PAM module ordering is correct (or faillock not in use)",
	}
}

func checkOrder(path string) *check.Result {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var faillockSeen, unixSeen bool
	var faillockLine, unixLine int
	lineNum := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		lineNum++

		if strings.HasPrefix(line, "auth") {
			if strings.Contains(line, "pam_faillock.so") && !faillockSeen {
				faillockSeen = true
				faillockLine = lineNum
			}
			if strings.Contains(line, "pam_unix.so") && !unixSeen {
				unixSeen = true
				unixLine = lineNum
			}
		}
	}

	if faillockSeen && unixSeen && faillockLine > unixLine {
		return &check.Result{
			Status:      check.Fail,
			Message:     "pam_faillock appears after pam_unix in " + path,
			Remediation: "Move pam_faillock.so before pam_unix.so in " + path,
		}
	}

	return nil
}
