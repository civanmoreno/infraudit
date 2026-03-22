package check

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// DefaultCmdTimeout is the default timeout for external commands.
	DefaultCmdTimeout = 30 * time.Second
	// LongCmdTimeout is used for commands that scan the entire filesystem.
	LongCmdTimeout = 60 * time.Second
)

// RunCmd executes a command with the given timeout and returns its combined output.
// If the command exceeds the timeout, it returns a clear error message.
func RunCmd(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("command timed out after %s: %s", timeout, name)
	}
	return out, err
}

// RunCmdOk executes a command with the given timeout and returns true if it succeeds.
func RunCmdOk(timeout time.Duration, name string, args ...string) bool {
	_, err := RunCmd(timeout, name, args...)
	return err == nil
}

// ServiceActive checks whether a systemd service is active.
func ServiceActive(name string) bool {
	out, err := RunCmd(DefaultCmdTimeout, "systemctl", "is-active", name)
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// ReadSysctl reads a sysctl value from the given /proc/sys path.
func ReadSysctl(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
