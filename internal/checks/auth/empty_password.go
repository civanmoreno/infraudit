package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&emptyPassword{})
}

type emptyPassword struct{}

func (c *emptyPassword) ID() string             { return "AUTH-004" }
func (c *emptyPassword) Name() string           { return "No users with empty password" }
func (c *emptyPassword) Category() string       { return "auth" }
func (c *emptyPassword) Severity() check.Severity { return check.Critical }
func (c *emptyPassword) Description() string    { return "Ensure no user accounts have an empty password field" }

func (c *emptyPassword) Run() check.Result {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/shadow: " + err.Error(),
		}
	}
	defer f.Close()

	var bad []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		user := parts[0]
		hash := parts[1]
		// Empty string means no password set (can login without password)
		if hash == "" {
			bad = append(bad, user)
		}
	}

	if err := scanner.Err(); err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Error reading /etc/shadow: " + err.Error(),
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("Users with empty password: %s", strings.Join(bad, ", ")),
			Remediation: "Lock these accounts with 'passwd -l <user>' or set a strong password",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No users have empty passwords",
	}
}
