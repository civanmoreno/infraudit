package check

import (
	"os"
	"os/exec"
	"strings"
)

// ServiceActive checks whether a systemd service is active.
func ServiceActive(name string) bool {
	out, err := exec.Command("systemctl", "is-active", name).CombinedOutput()
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
