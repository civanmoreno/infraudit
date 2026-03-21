package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&systemShell{})
}

type systemShell struct{}

func (c *systemShell) ID() string             { return "AUTH-005" }
func (c *systemShell) Name() string           { return "System accounts have nologin shell" }
func (c *systemShell) Category() string       { return "auth" }
func (c *systemShell) Severity() check.Severity { return check.High }
func (c *systemShell) Description() string    { return "Ensure system/service accounts use /sbin/nologin or /bin/false" }

func (c *systemShell) Run() check.Result {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/passwd: " + err.Error(),
		}
	}
	defer f.Close()

	// Shells considered safe for system accounts
	safeShells := map[string]bool{
		"/sbin/nologin":  true,
		"/usr/sbin/nologin": true,
		"/bin/false":     true,
		"/usr/bin/false": true,
	}

	// Accounts that are allowed to have a login shell
	allowed := map[string]bool{
		"root": true,
		"sync": true,
	}

	var bad []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		user := parts[0]
		uid := parts[2]
		shell := parts[6]

		if allowed[user] {
			continue
		}

		// System accounts typically have UID < 1000
		if uid >= "1000" {
			continue
		}

		// Parse UID as number for correct comparison
		var uidNum int
		fmt.Sscanf(uid, "%d", &uidNum)
		if uidNum >= 1000 {
			continue
		}

		if shell == "" || safeShells[shell] {
			continue
		}

		bad = append(bad, fmt.Sprintf("%s (shell: %s)", user, shell))
	}

	if err := scanner.Err(); err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Error reading /etc/passwd: " + err.Error(),
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("System accounts with login shell: %s", strings.Join(bad, ", ")),
			Remediation: "Set shell to /sbin/nologin or /bin/false with 'usermod -s /sbin/nologin <user>'",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "All system accounts have non-login shells",
	}
}
