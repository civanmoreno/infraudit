package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&uidZero{})
}

type uidZero struct{}

func (c *uidZero) ID() string             { return "AUTH-003" }
func (c *uidZero) Name() string           { return "Only root has UID 0" }
func (c *uidZero) Category() string       { return "auth" }
func (c *uidZero) Severity() check.Severity { return check.Critical }
func (c *uidZero) Description() string    { return "Ensure no user besides root has UID 0" }

func (c *uidZero) Run() check.Result {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/passwd: " + err.Error(),
		}
	}
	defer f.Close()

	var bad []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		user := parts[0]
		uid := parts[2]
		if uid == "0" && user != "root" {
			bad = append(bad, user)
		}
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
			Message:     fmt.Sprintf("Non-root users with UID 0: %s", strings.Join(bad, ", ")),
			Remediation: "Remove or change the UID of these accounts so only root has UID 0",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "Only root has UID 0",
	}
}
