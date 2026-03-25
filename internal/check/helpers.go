package check

import (
	"bufio"
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

// PasswdEntry represents a parsed line from /etc/passwd.
type PasswdEntry struct {
	User  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// ParsePasswd reads /etc/passwd and returns parsed entries.
func ParsePasswd() ([]PasswdEntry, error) {
	return parseColonFile("/etc/passwd", func(parts []string) *PasswdEntry {
		if len(parts) < 7 {
			return nil
		}
		uid, err := fmt.Sscanf(parts[2], "%d", new(int))
		if uid == 0 || err != nil {
			return nil
		}
		var uidNum, gidNum int
		fmt.Sscanf(parts[2], "%d", &uidNum)
		fmt.Sscanf(parts[3], "%d", &gidNum)
		return &PasswdEntry{User: parts[0], UID: uidNum, GID: gidNum, Home: parts[5], Shell: parts[6]}
	})
}

// ShadowEntry represents a parsed line from /etc/shadow.
type ShadowEntry struct {
	User string
	Hash string
}

// ParseShadow reads /etc/shadow and returns parsed entries.
func ParseShadow() ([]ShadowEntry, error) {
	return parseColonFile("/etc/shadow", func(parts []string) *ShadowEntry {
		if len(parts) < 2 {
			return nil
		}
		return &ShadowEntry{User: parts[0], Hash: parts[1]}
	})
}

// parseColonFile is a generic colon-separated file parser.
func parseColonFile[T any](path string, parse func([]string) *T) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []T
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if entry := parse(parts); entry != nil {
			entries = append(entries, *entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return entries, err
	}
	return entries, nil
}

// MountEntry represents a parsed line from /proc/mounts.
type MountEntry struct {
	Device  string
	Mount   string
	FSType  string
	Options string
}

// ParseMounts reads /proc/mounts and returns parsed entries.
func ParseMounts() []MountEntry {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()

	var mounts []MountEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		mounts = append(mounts, MountEntry{
			Device: fields[0], Mount: fields[1],
			FSType: fields[2], Options: fields[3],
		})
	}
	return mounts
}

// HasMountOption checks if a comma-separated option string contains the given option.
func HasMountOption(opts, opt string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == opt {
			return true
		}
	}
	return false
}
