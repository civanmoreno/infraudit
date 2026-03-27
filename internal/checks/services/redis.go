package services

import (
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&redisAuth{})
}

// SVC-057: Redis requires authentication
type redisAuth struct{}

func (c *redisAuth) ID() string               { return "SVC-057" }
func (c *redisAuth) Name() string             { return "Redis requires authentication" }
func (c *redisAuth) Category() string         { return "services" }
func (c *redisAuth) Severity() check.Severity { return check.High }
func (c *redisAuth) Description() string {
	return "Ensure Redis is configured with requirepass to prevent unauthenticated access"
}

func (c *redisAuth) Run() check.Result {
	configPaths := []string{
		"/etc/redis/redis.conf",
		"/etc/redis.conf",
	}

	var found string
	for _, p := range configPaths {
		if _, err := os.Stat(check.P(p)); err == nil {
			found = p
			break
		}
	}

	if found == "" {
		return check.Result{
			Status:  check.Pass,
			Message: "Redis is not installed or no config file found",
		}
	}

	data, err := os.ReadFile(check.P(found))
	if err != nil {
		return check.Result{
			Status:      check.Error,
			Message:     "Cannot read Redis config: " + err.Error(),
			Remediation: "Run infraudit with sudo for full results",
		}
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "requirepass ") {
			pass := strings.TrimPrefix(line, "requirepass ")
			pass = strings.TrimSpace(pass)
			if pass != "" && pass != `""` && pass != "''" {
				return check.Result{
					Status:  check.Pass,
					Message: "Redis requirepass is configured",
				}
			}
		}
	}

	return check.Result{
		Status:      check.Fail,
		Message:     "Redis does not require authentication (" + found + ")",
		Remediation: "Set 'requirepass <strong-password>' in " + found + " and restart Redis",
	}
}
