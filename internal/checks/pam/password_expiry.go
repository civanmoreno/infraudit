package pam

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&passwordExpiry{})
}

type passwordExpiry struct{}

func (c *passwordExpiry) ID() string             { return "PAM-005" }
func (c *passwordExpiry) Name() string           { return "Password expiration configured" }
func (c *passwordExpiry) Category() string       { return "pam" }
func (c *passwordExpiry) Severity() check.Severity { return check.Low }
func (c *passwordExpiry) Description() string {
	return "Verify password aging is configured in /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE)"
}

func (c *passwordExpiry) Run() check.Result {
	f, err := os.Open("/etc/login.defs")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/login.defs: " + err.Error(),
		}
	}
	defer f.Close()

	defs := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			defs[fields[0]] = fields[1]
		}
	}

	var issues []string

	maxDays := atoi(defs["PASS_MAX_DAYS"])
	if maxDays == 0 || maxDays > 365 {
		issues = append(issues, fmt.Sprintf("PASS_MAX_DAYS=%s (recommended <= 365)", defs["PASS_MAX_DAYS"]))
	}

	minDays := atoi(defs["PASS_MIN_DAYS"])
	if minDays < 1 {
		issues = append(issues, fmt.Sprintf("PASS_MIN_DAYS=%s (recommended >= 1)", defs["PASS_MIN_DAYS"]))
	}

	warnAge := atoi(defs["PASS_WARN_AGE"])
	if warnAge < 7 {
		issues = append(issues, fmt.Sprintf("PASS_WARN_AGE=%s (recommended >= 7)", defs["PASS_WARN_AGE"]))
	}

	if len(issues) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "Password aging needs adjustment: " + strings.Join(issues, ", "),
			Remediation: "Set PASS_MAX_DAYS=365, PASS_MIN_DAYS=1, PASS_WARN_AGE=7 in /etc/login.defs",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: fmt.Sprintf("Password aging configured (max=%d, min=%d, warn=%d)", maxDays, minDays, warnAge),
	}
}
