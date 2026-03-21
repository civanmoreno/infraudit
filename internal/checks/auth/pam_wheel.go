package auth

import (
	"bufio"
	"os"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&pamWheel{})
}

type pamWheel struct{}

func (c *pamWheel) ID() string             { return "AUTH-008" }
func (c *pamWheel) Name() string           { return "su restricted via pam_wheel" }
func (c *pamWheel) Category() string       { return "auth" }
func (c *pamWheel) Severity() check.Severity { return check.Medium }
func (c *pamWheel) Description() string    { return "Ensure su command is restricted to an authorized group via pam_wheel.so" }

func (c *pamWheel) Run() check.Result {
	f, err := os.Open("/etc/pam.d/su")
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: "Could not read /etc/pam.d/su: " + err.Error(),
		}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.Contains(line, "pam_wheel.so") {
			// Check it's a required/requisite auth line
			if strings.HasPrefix(line, "auth") &&
				(strings.Contains(line, "required") || strings.Contains(line, "requisite")) {
				return check.Result{
					Status:  check.Pass,
					Message: "su is restricted via pam_wheel.so",
				}
			}
		}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "su is not restricted via pam_wheel.so",
		Remediation: "Uncomment or add 'auth required pam_wheel.so use_uid' in /etc/pam.d/su",
	}
}
