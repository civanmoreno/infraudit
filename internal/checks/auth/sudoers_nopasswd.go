package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&sudoersNopasswd{})
}

type sudoersNopasswd struct{}

func (c *sudoersNopasswd) ID() string               { return "AUTH-006" }
func (c *sudoersNopasswd) Name() string             { return "No excessive NOPASSWD in sudoers" }
func (c *sudoersNopasswd) Category() string         { return "auth" }
func (c *sudoersNopasswd) Severity() check.Severity { return check.High }
func (c *sudoersNopasswd) Description() string {
	return "Check for excessive use of NOPASSWD in sudoers configuration"
}

func (c *sudoersNopasswd) Run() check.Result {
	paths := []string{check.P("/etc/sudoers")}

	// Also check sudoers.d drop-ins
	entries, err := os.ReadDir(check.P("/etc/sudoers.d"))
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				paths = append(paths, check.P("/etc/sudoers.d/"+e.Name()))
			}
		}
	}

	var findings []string
	for _, path := range paths {
		matches, err := scanForNopasswd(path)
		if err != nil {
			continue
		}
		for _, m := range matches {
			findings = append(findings, fmt.Sprintf("%s: %s", path, m))
		}
	}

	if len(findings) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Found %d NOPASSWD entries in sudoers", len(findings)),
			Remediation: "Review NOPASSWD entries and remove unnecessary ones. Require password for sensitive commands.",
			Details:     map[string]string{"entries": strings.Join(findings, "\n")},
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No NOPASSWD entries found in sudoers",
	}
}

func scanForNopasswd(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
			matches = append(matches, line)
		}
	}
	return matches, scanner.Err()
}
