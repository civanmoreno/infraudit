package filesystem

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&mountOptions{})
	check.Register(&devShmMount{})
	check.Register(&tmpPartition{})
	check.Register(&varTmpMount{})
	check.Register(&tmpMount{})
}

type mountEntry struct {
	device  string
	mount   string
	fstype  string
	options string
}

func parseMounts() []mountEntry {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()

	var mounts []mountEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		mounts = append(mounts, mountEntry{
			device: fields[0], mount: fields[1],
			fstype: fields[2], options: fields[3],
		})
	}
	return mounts
}

func findMount(mounts []mountEntry, path string) *mountEntry {
	for i := range mounts {
		if mounts[i].mount == path {
			return &mounts[i]
		}
	}
	return nil
}

func hasOption(opts, opt string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == opt {
			return true
		}
	}
	return false
}

// FS-004: Sensitive partitions mount options
type mountOptions struct{}

func (c *mountOptions) ID() string             { return "FS-004" }
func (c *mountOptions) Name() string           { return "Sensitive partitions have restrictive mount options" }
func (c *mountOptions) Category() string       { return "filesystem" }
func (c *mountOptions) Severity() check.Severity { return check.Medium }
func (c *mountOptions) Description() string    { return "Verify /tmp, /var, /home have noexec/nosuid/nodev where appropriate" }

func (c *mountOptions) Run() check.Result {
	mounts := parseMounts()
	type req struct {
		path string
		opts []string
	}
	checks := []req{
		{"/tmp", []string{"nodev", "nosuid", "noexec"}},
		{"/var/tmp", []string{"nodev", "nosuid", "noexec"}},
		{"/home", []string{"nodev", "nosuid"}},
	}

	var issues []string
	for _, r := range checks {
		m := findMount(mounts, r.path)
		if m == nil {
			continue // Not a separate partition
		}
		for _, opt := range r.opts {
			if !hasOption(m.options, opt) {
				issues = append(issues, fmt.Sprintf("%s missing %s", r.path, opt))
			}
		}
	}

	if len(issues) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     strings.Join(issues, "; "),
			Remediation: "Add missing mount options in /etc/fstab and remount",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "Sensitive partitions have appropriate mount options",
	}
}

// FS-005: /dev/shm mount options
type devShmMount struct{}

func (c *devShmMount) ID() string             { return "FS-005" }
func (c *devShmMount) Name() string           { return "/dev/shm mounted with nodev,nosuid,noexec" }
func (c *devShmMount) Category() string       { return "filesystem" }
func (c *devShmMount) Severity() check.Severity { return check.Medium }
func (c *devShmMount) Description() string    { return "Verify /dev/shm has restrictive mount options" }

func (c *devShmMount) Run() check.Result {
	mounts := parseMounts()
	m := findMount(mounts, "/dev/shm")
	if m == nil {
		return check.Result{Status: check.Warn, Message: "/dev/shm is not mounted as a separate filesystem"}
	}

	required := []string{"nodev", "nosuid", "noexec"}
	var missing []string
	for _, opt := range required {
		if !hasOption(m.options, opt) {
			missing = append(missing, opt)
		}
	}

	if len(missing) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "/dev/shm missing options: " + strings.Join(missing, ", "),
			Remediation: "Add 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' to /etc/fstab",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: "/dev/shm has nodev, nosuid, noexec",
	}
}

// FS-009: /tmp separate partition
type tmpPartition struct{}

func (c *tmpPartition) ID() string             { return "FS-009" }
func (c *tmpPartition) Name() string           { return "/tmp on separate partition or tmpfs" }
func (c *tmpPartition) Category() string       { return "filesystem" }
func (c *tmpPartition) Severity() check.Severity { return check.Medium }
func (c *tmpPartition) Description() string    { return "Verify /tmp is a separate partition or tmpfs" }

func (c *tmpPartition) Run() check.Result {
	mounts := parseMounts()
	m := findMount(mounts, "/tmp")
	if m == nil {
		return check.Result{
			Status:      check.Warn,
			Message:     "/tmp is not a separate partition",
			Remediation: "Create a separate /tmp partition or enable tmp.mount for tmpfs",
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: fmt.Sprintf("/tmp is mounted as %s (%s)", m.fstype, m.device),
	}
}

// FS-010: /var/tmp mount options
type varTmpMount struct{}

func (c *varTmpMount) ID() string             { return "FS-010" }
func (c *varTmpMount) Name() string           { return "/var/tmp with nodev,nosuid,noexec" }
func (c *varTmpMount) Category() string       { return "filesystem" }
func (c *varTmpMount) Severity() check.Severity { return check.Medium }
func (c *varTmpMount) Description() string    { return "Verify /var/tmp has restrictive mount options" }

func (c *varTmpMount) Run() check.Result {
	mounts := parseMounts()
	m := findMount(mounts, "/var/tmp")
	if m == nil {
		return check.Result{
			Status:  check.Warn,
			Message: "/var/tmp is not a separate partition",
		}
	}

	required := []string{"nodev", "nosuid", "noexec"}
	var missing []string
	for _, opt := range required {
		if !hasOption(m.options, opt) {
			missing = append(missing, opt)
		}
	}

	if len(missing) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "/var/tmp missing: " + strings.Join(missing, ", "),
			Remediation: "Add nodev,nosuid,noexec to /var/tmp in /etc/fstab",
		}
	}

	return check.Result{Status: check.Pass, Message: "/var/tmp has nodev, nosuid, noexec"}
}

// FS-011: tmp.mount enabled
type tmpMount struct{}

func (c *tmpMount) ID() string             { return "FS-011" }
func (c *tmpMount) Name() string           { return "systemd tmp.mount enabled" }
func (c *tmpMount) Category() string       { return "filesystem" }
func (c *tmpMount) Severity() check.Severity { return check.Low }
func (c *tmpMount) Description() string    { return "Verify tmp.mount is enabled if using systemd for /tmp" }

func (c *tmpMount) Run() check.Result {
	mounts := parseMounts()
	m := findMount(mounts, "/tmp")
	if m != nil {
		return check.Result{Status: check.Pass, Message: "/tmp is already a separate mount"}
	}

	if serviceActive("tmp.mount") {
		return check.Result{Status: check.Pass, Message: "tmp.mount is active"}
	}

	return check.Result{
		Status:      check.Warn,
		Message:     "tmp.mount is not active and /tmp is not a separate partition",
		Remediation: "Enable tmp.mount: 'systemctl enable --now tmp.mount'",
	}
}
