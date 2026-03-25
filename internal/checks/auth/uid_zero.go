package auth

import (
	"fmt"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&uidZero{})
}

type uidZero struct{}

func (c *uidZero) ID() string               { return "AUTH-003" }
func (c *uidZero) Name() string             { return "Only root has UID 0" }
func (c *uidZero) Category() string         { return "auth" }
func (c *uidZero) Severity() check.Severity { return check.Critical }
func (c *uidZero) Description() string      { return "Ensure no user besides root has UID 0" }

func (c *uidZero) Run() check.Result {
	entries, err := check.ParsePasswd()
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/passwd: " + err.Error(),
		}
	}

	var bad []string
	for _, e := range entries {
		if e.UID == 0 && e.User != "root" {
			bad = append(bad, e.User)
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
