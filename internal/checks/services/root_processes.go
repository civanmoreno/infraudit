package services

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&rootProcesses{})
}

type rootProcesses struct{}

func (c *rootProcesses) ID() string             { return "SVC-008" }
func (c *rootProcesses) Name() string           { return "No unnecessary processes running as root" }
func (c *rootProcesses) Category() string       { return "services" }
func (c *rootProcesses) Severity() check.Severity { return check.Medium }
func (c *rootProcesses) Description() string    { return "List processes running as root for review" }

// Processes expected to run as root
var expectedRoot = map[string]bool{
	"init": true, "systemd": true, "kthreadd": true,
	"sshd": true, "agetty": true, "login": true,
	"cron": true, "crond": true, "atd": true,
	"auditd": true, "rsyslogd": true, "journald": true,
	"systemd-journald": true, "systemd-logind": true,
	"systemd-udevd": true, "systemd-resolved": true,
	"systemd-timesyncd": true, "networkd": true,
	"polkitd": true, "dbus-daemon": true,
	"containerd": true, "dockerd": true,
	"snapd": true, "multipathd": true,
	"irqbalance": true, "thermald": true,
}

func (c *rootProcesses) Run() check.Result {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /proc: " + err.Error()}
	}

	var unexpected []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		// Only numeric dirs (PIDs)
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}

		status := readProcStatus(filepath.Join("/proc", pid, "status"))
		if status["Uid"] == "" {
			continue
		}
		// Check if running as UID 0
		uidFields := strings.Fields(status["Uid"])
		if len(uidFields) == 0 || uidFields[0] != "0" {
			continue
		}

		name := status["Name"]
		if name == "" || expectedRoot[name] {
			continue
		}
		// Skip kernel threads (PPid 2 or kthreadd children)
		if status["PPid"] == "2" {
			continue
		}

		unexpected = append(unexpected, name)
		if len(unexpected) >= 20 {
			break
		}
	}

	if len(unexpected) > 0 {
		// Deduplicate
		seen := make(map[string]bool)
		var unique []string
		for _, n := range unexpected {
			if !seen[n] {
				seen[n] = true
				unique = append(unique, n)
			}
		}
		return check.Result{
			Status:  check.Warn,
			Message: fmt.Sprintf("Processes running as root (review recommended): %s", strings.Join(unique, ", ")),
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "No unexpected processes running as root",
	}
}

func readProcStatus(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	status := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":\t", 2)
		if len(parts) == 2 {
			status[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return status
}
