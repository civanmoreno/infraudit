package rlimit

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&openFiles{})
	check.Register(&maxProcs{})
	check.Register(&stackSize{})
	check.Register(&wildcardUnlimited{})
	check.Register(&rootDisk{})
	check.Register(&varDisk{})
	check.Register(&inodeUsage{})
}

// RLIM-001
type openFiles struct{}

func (c *openFiles) ID() string             { return "RLIM-001" }
func (c *openFiles) Name() string           { return "Open files limit is reasonable" }
func (c *openFiles) Category() string       { return "rlimit" }
func (c *openFiles) Severity() check.Severity { return check.Low }
func (c *openFiles) Description() string    { return "Check system-wide open files limit" }

func (c *openFiles) Run() check.Result {
	data, err := os.ReadFile("/proc/sys/fs/file-max")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read file-max"}
	}
	max, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	if max < 65536 {
		return check.Result{
			Status:  check.Warn,
			Message: fmt.Sprintf("file-max is low (%d)", max),
			Remediation: "Increase: sysctl -w fs.file-max=262144",
		}
	}
	return check.Result{Status: check.Pass, Message: fmt.Sprintf("file-max = %d", max)}
}

// RLIM-002
type maxProcs struct{}

func (c *maxProcs) ID() string             { return "RLIM-002" }
func (c *maxProcs) Name() string           { return "Max user processes limit set" }
func (c *maxProcs) Category() string       { return "rlimit" }
func (c *maxProcs) Severity() check.Severity { return check.Medium }
func (c *maxProcs) Description() string    { return "Verify nproc limits protect against fork bombs" }

func (c *maxProcs) Run() check.Result {
	data, err := os.ReadFile("/etc/security/limits.conf")
	if err != nil {
		return check.Result{Status: check.Warn, Message: "Cannot read limits.conf"}
	}

	if strings.Contains(string(data), "nproc") {
		return check.Result{Status: check.Pass, Message: "nproc limits are configured in limits.conf"}
	}

	// Check limits.d
	entries, _ := os.ReadDir("/etc/security/limits.d")
	for _, e := range entries {
		d, _ := os.ReadFile("/etc/security/limits.d/" + e.Name())
		if strings.Contains(string(d), "nproc") {
			return check.Result{Status: check.Pass, Message: "nproc limits configured in limits.d/" + e.Name()}
		}
	}

	return check.Result{
		Status: check.Warn, Message: "No nproc limits configured",
		Remediation: "Add '* hard nproc 4096' to /etc/security/limits.conf",
	}
}

// RLIM-003
type stackSize struct{}

func (c *stackSize) ID() string             { return "RLIM-003" }
func (c *stackSize) Name() string           { return "Stack size limits configured" }
func (c *stackSize) Category() string       { return "rlimit" }
func (c *stackSize) Severity() check.Severity { return check.Low }
func (c *stackSize) Description() string    { return "Verify stack size limits are set" }

func (c *stackSize) Run() check.Result {
	data, _ := os.ReadFile("/etc/security/limits.conf")
	if strings.Contains(string(data), "stack") {
		return check.Result{Status: check.Pass, Message: "Stack size limits configured"}
	}
	return check.Result{Status: check.Pass, Message: "Default stack size limits are adequate"}
}

// RLIM-004
type wildcardUnlimited struct{}

func (c *wildcardUnlimited) ID() string             { return "RLIM-004" }
func (c *wildcardUnlimited) Name() string           { return "No wildcard unlimited entries" }
func (c *wildcardUnlimited) Category() string       { return "rlimit" }
func (c *wildcardUnlimited) Severity() check.Severity { return check.Medium }
func (c *wildcardUnlimited) Description() string    { return "Verify no wildcard unlimited entries in limits.conf" }

func (c *wildcardUnlimited) Run() check.Result {
	files := []string{"/etc/security/limits.conf"}
	entries, _ := os.ReadDir("/etc/security/limits.d")
	for _, e := range entries {
		files = append(files, "/etc/security/limits.d/"+e.Name())
	}

	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			if strings.HasPrefix(line, "*") && strings.Contains(line, "unlimited") {
				f.Close()
				return check.Result{
					Status:      check.Warn,
					Message:     "Wildcard unlimited entry found in " + path,
					Remediation: "Replace wildcard unlimited with specific values",
				}
			}
		}
		f.Close()
	}
	return check.Result{Status: check.Pass, Message: "No wildcard unlimited entries in limits.conf"}
}

// RLIM-005
type rootDisk struct{}

func (c *rootDisk) ID() string             { return "RLIM-005" }
func (c *rootDisk) Name() string           { return "Root filesystem space below 85%" }
func (c *rootDisk) Category() string       { return "rlimit" }
func (c *rootDisk) Severity() check.Severity { return check.High }
func (c *rootDisk) Description() string    { return "Verify root filesystem usage is below 85%" }

func (c *rootDisk) Run() check.Result {
	usage := getDiskUsage("/")
	if usage < 0 {
		return check.Result{Status: check.Error, Message: "Cannot determine disk usage"}
	}
	if usage >= 85 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("Root filesystem usage is %d%%", usage),
			Remediation: "Free disk space or expand the partition",
		}
	}
	return check.Result{Status: check.Pass, Message: fmt.Sprintf("Root filesystem usage: %d%%", usage)}
}

// RLIM-006
type varDisk struct{}

func (c *varDisk) ID() string             { return "RLIM-006" }
func (c *varDisk) Name() string           { return "/var, /var/log, /tmp have sufficient space" }
func (c *varDisk) Category() string       { return "rlimit" }
func (c *varDisk) Severity() check.Severity { return check.Medium }
func (c *varDisk) Description() string    { return "Verify key directories have sufficient disk space" }

func (c *varDisk) Run() check.Result {
	var high []string
	for _, dir := range []string{"/var", "/var/log", "/tmp"} {
		usage := getDiskUsage(dir)
		if usage >= 85 {
			high = append(high, fmt.Sprintf("%s (%d%%)", dir, usage))
		}
	}
	if len(high) > 0 {
		return check.Result{
			Status:  check.Warn,
			Message: "High disk usage: " + strings.Join(high, ", "),
		}
	}
	return check.Result{Status: check.Pass, Message: "Key directories have sufficient disk space"}
}

// RLIM-007
type inodeUsage struct{}

func (c *inodeUsage) ID() string             { return "RLIM-007" }
func (c *inodeUsage) Name() string           { return "Inode usage is not exhausted" }
func (c *inodeUsage) Category() string       { return "rlimit" }
func (c *inodeUsage) Severity() check.Severity { return check.High }
func (c *inodeUsage) Description() string    { return "Verify inode usage is below critical levels" }

func (c *inodeUsage) Run() check.Result {
	out, err := exec.Command("df", "-i", "--output=ipcent,target").CombinedOutput()
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot check inode usage"}
	}

	var high []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "IUse%" {
			continue
		}
		pct := strings.TrimSuffix(fields[0], "%")
		val, _ := strconv.Atoi(pct)
		if val >= 85 {
			high = append(high, fmt.Sprintf("%s (%d%%)", fields[1], val))
		}
	}

	if len(high) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "High inode usage: " + strings.Join(high, ", "),
			Remediation: "Clean up small files or expand filesystem",
		}
	}
	return check.Result{Status: check.Pass, Message: "Inode usage is within normal levels"}
}

func getDiskUsage(path string) int {
	out, err := exec.Command("df", "--output=pcent", path).CombinedOutput()
	if err != nil {
		return -1
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return -1
	}
	pct := strings.TrimSpace(strings.TrimSuffix(lines[1], "%"))
	val, _ := strconv.Atoi(pct)
	return val
}
