package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&dockerDetect{})
	check.Register(&dockerDaemonConfig{})
	check.Register(&dockerSocketPerms{})
	check.Register(&rootContainers{})
	check.Register(&privilegedContainers{})
	check.Register(&resourceLimits{})
	check.Register(&contentTrust{})
	check.Register(&iccDisabled{})
	check.Register(&readonlyRootfs{})
	check.Register(&loggingDriver{})
	check.Register(&trustedRegistries{})
}

func dockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

func podmanAvailable() bool {
	_, err := exec.LookPath("podman")
	return err == nil
}

func runtimeAvailable() string {
	if dockerAvailable() {
		return "docker"
	}
	if podmanAvailable() {
		return "podman"
	}
	return ""
}

// CTR-001
type dockerDetect struct{}

func (c *dockerDetect) ID() string               { return "CTR-001" }
func (c *dockerDetect) Name() string             { return "Docker/Podman detected" }
func (c *dockerDetect) Category() string         { return "container" }
func (c *dockerDetect) Severity() check.Severity { return check.Info }
func (c *dockerDetect) Description() string      { return "Detect if Docker or Podman is installed" }

func (c *dockerDetect) Run() check.Result {
	rt := runtimeAvailable()
	if rt == "" {
		return check.Result{Status: check.Pass, Message: "No container runtime installed"}
	}
	return check.Result{Status: check.Pass, Message: rt + " is installed"}
}

// CTR-002
type dockerDaemonConfig struct{}

func (c *dockerDaemonConfig) ID() string               { return "CTR-002" }
func (c *dockerDaemonConfig) Name() string             { return "Docker daemon configuration reviewed" }
func (c *dockerDaemonConfig) Category() string         { return "container" }
func (c *dockerDaemonConfig) Severity() check.Severity { return check.Medium }
func (c *dockerDaemonConfig) Description() string {
	return "Verify Docker daemon.json has security settings"
}

func (c *dockerDaemonConfig) Run() check.Result {
	if !dockerAvailable() {
		return check.Result{Status: check.Pass, Message: "Docker not installed (skipped)"}
	}

	data, err := os.ReadFile("/etc/docker/daemon.json")
	if err != nil {
		return check.Result{
			Status: check.Warn, Message: "Docker daemon.json not found",
			Remediation: "Create /etc/docker/daemon.json with security settings",
		}
	}

	var conf map[string]interface{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return check.Result{Status: check.Warn, Message: "Invalid daemon.json: " + err.Error()}
	}

	return check.Result{Status: check.Pass, Message: "Docker daemon.json exists"}
}

// CTR-003
type dockerSocketPerms struct{}

func (c *dockerSocketPerms) ID() string               { return "CTR-003" }
func (c *dockerSocketPerms) Name() string             { return "Docker socket permissions restricted" }
func (c *dockerSocketPerms) Category() string         { return "container" }
func (c *dockerSocketPerms) Severity() check.Severity { return check.High }
func (c *dockerSocketPerms) Description() string {
	return "Verify /var/run/docker.sock is not world-accessible"
}

func (c *dockerSocketPerms) Run() check.Result {
	if !dockerAvailable() {
		return check.Result{Status: check.Pass, Message: "Docker not installed (skipped)"}
	}

	info, err := os.Stat("/var/run/docker.sock")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "Docker socket not found"}
	}

	perm := info.Mode().Perm()
	if perm&0006 != 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("Docker socket is world-accessible (%04o)", perm),
			Remediation: "Fix: chmod 660 /var/run/docker.sock",
		}
	}
	return check.Result{Status: check.Pass, Message: "Docker socket permissions are restricted"}
}

// CTR-004
type rootContainers struct{}

func (c *rootContainers) ID() string               { return "CTR-004" }
func (c *rootContainers) Name() string             { return "No containers running as root" }
func (c *rootContainers) Category() string         { return "container" }
func (c *rootContainers) Severity() check.Severity { return check.High }
func (c *rootContainers) Description() string      { return "Check for containers running as root user" }

func (c *rootContainers) Run() check.Result {
	rt := runtimeAvailable()
	if rt == "" {
		return check.Result{Status: check.Pass, Message: "No container runtime (skipped)"}
	}

	out, err := check.RunCmd(check.DefaultCmdTimeout, rt, "ps", "--format", "{{.ID}} {{.Names}}")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "No running containers"}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var rootCtnrs []string
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		id := fields[0]
		inspOut, _ := check.RunCmd(check.DefaultCmdTimeout, rt, "inspect", "--format", "{{.Config.User}}", id)
		user := strings.TrimSpace(string(inspOut))
		if user == "" || user == "0" || user == "root" {
			name := id
			if len(fields) > 1 {
				name = fields[1]
			}
			rootCtnrs = append(rootCtnrs, name)
		}
	}

	if len(rootCtnrs) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("%d container(s) running as root: %s", len(rootCtnrs), strings.Join(rootCtnrs, ", ")),
			Remediation: "Set USER directive in Dockerfile or use --user flag at runtime",
			Details:     map[string]string{"containers": strings.Join(rootCtnrs, "\n")},
		}
	}
	return check.Result{Status: check.Pass, Message: "No containers running as root"}
}

// CTR-005
type privilegedContainers struct{}

func (c *privilegedContainers) ID() string               { return "CTR-005" }
func (c *privilegedContainers) Name() string             { return "No privileged containers" }
func (c *privilegedContainers) Category() string         { return "container" }
func (c *privilegedContainers) Severity() check.Severity { return check.Critical }
func (c *privilegedContainers) Description() string {
	return "Check for containers running in privileged mode"
}

func (c *privilegedContainers) Run() check.Result {
	rt := runtimeAvailable()
	if rt == "" {
		return check.Result{Status: check.Pass, Message: "No container runtime (skipped)"}
	}

	out, err := check.RunCmd(check.DefaultCmdTimeout, rt, "ps", "-q")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return check.Result{Status: check.Pass, Message: "No running containers"}
	}

	ids := strings.Fields(strings.TrimSpace(string(out)))
	var priv []string
	for _, id := range ids {
		inspOut, _ := check.RunCmd(check.DefaultCmdTimeout, rt, "inspect", "--format", "{{.HostConfig.Privileged}}", id)
		if strings.TrimSpace(string(inspOut)) == "true" {
			priv = append(priv, id[:12])
		}
	}

	if len(priv) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("%d privileged container(s): %s", len(priv), strings.Join(priv, ", ")),
			Remediation: "Remove --privileged flag and use specific capabilities instead (--cap-add)",
			Details:     map[string]string{"containers": strings.Join(priv, "\n")},
		}
	}
	return check.Result{Status: check.Pass, Message: "No privileged containers"}
}

// CTR-006
type resourceLimits struct{}

func (c *resourceLimits) ID() string               { return "CTR-006" }
func (c *resourceLimits) Name() string             { return "Container resource limits set" }
func (c *resourceLimits) Category() string         { return "container" }
func (c *resourceLimits) Severity() check.Severity { return check.Medium }
func (c *resourceLimits) Description() string      { return "Verify containers have CPU and memory limits" }

func (c *resourceLimits) Run() check.Result {
	rt := runtimeAvailable()
	if rt == "" {
		return check.Result{Status: check.Pass, Message: "No container runtime (skipped)"}
	}

	out, err := check.RunCmd(check.DefaultCmdTimeout, rt, "ps", "-q")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return check.Result{Status: check.Pass, Message: "No running containers"}
	}

	ids := strings.Fields(strings.TrimSpace(string(out)))
	var noLimits []string
	for _, id := range ids {
		memOut, _ := check.RunCmd(check.DefaultCmdTimeout, rt, "inspect", "--format", "{{.HostConfig.Memory}}", id)
		mem := strings.TrimSpace(string(memOut))
		if mem == "0" || mem == "" {
			noLimits = append(noLimits, id[:12])
		}
	}

	if len(noLimits) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("%d container(s) without memory limits", len(noLimits)),
			Remediation: "Set limits: --memory and --cpus flags",
			Details:     map[string]string{"containers": strings.Join(noLimits, "\n")},
		}
	}
	return check.Result{Status: check.Pass, Message: "All containers have resource limits"}
}

// CTR-007
type contentTrust struct{}

func (c *contentTrust) ID() string               { return "CTR-007" }
func (c *contentTrust) Name() string             { return "Docker content trust enabled" }
func (c *contentTrust) Category() string         { return "container" }
func (c *contentTrust) Severity() check.Severity { return check.Medium }
func (c *contentTrust) Description() string      { return "Verify DOCKER_CONTENT_TRUST is enabled" }

func (c *contentTrust) Run() check.Result {
	if !dockerAvailable() {
		return check.Result{Status: check.Pass, Message: "Docker not installed (skipped)"}
	}
	if os.Getenv("DOCKER_CONTENT_TRUST") == "1" {
		return check.Result{Status: check.Pass, Message: "Docker content trust is enabled"}
	}
	return check.Result{
		Status: check.Warn, Message: "DOCKER_CONTENT_TRUST is not enabled",
		Remediation: "Set DOCKER_CONTENT_TRUST=1 in environment",
	}
}

// CTR-008
type iccDisabled struct{}

func (c *iccDisabled) ID() string               { return "CTR-008" }
func (c *iccDisabled) Name() string             { return "Inter-container communication restricted" }
func (c *iccDisabled) Category() string         { return "container" }
func (c *iccDisabled) Severity() check.Severity { return check.Medium }
func (c *iccDisabled) Description() string      { return "Verify ICC is disabled on default bridge network" }

func (c *iccDisabled) Run() check.Result {
	if !dockerAvailable() {
		return check.Result{Status: check.Pass, Message: "Docker not installed (skipped)"}
	}

	data, err := os.ReadFile("/etc/docker/daemon.json")
	if err != nil {
		return check.Result{Status: check.Warn, Message: "No daemon.json to check ICC setting", Remediation: "Create /etc/docker/daemon.json with {\"icc\": false}"}
	}

	var conf map[string]interface{}
	_ = json.Unmarshal(data, &conf)
	if icc, ok := conf["icc"]; ok {
		if icc == false {
			return check.Result{Status: check.Pass, Message: "ICC is disabled"}
		}
	}

	return check.Result{
		Status: check.Warn, Message: "ICC may be enabled on default bridge",
		Remediation: "Add '\"icc\": false' to /etc/docker/daemon.json",
	}
}

// CTR-009
type readonlyRootfs struct{}

func (c *readonlyRootfs) ID() string               { return "CTR-009" }
func (c *readonlyRootfs) Name() string             { return "Read-only root filesystem in containers" }
func (c *readonlyRootfs) Category() string         { return "container" }
func (c *readonlyRootfs) Severity() check.Severity { return check.Low }
func (c *readonlyRootfs) Description() string {
	return "Check if containers use read-only root filesystem"
}

func (c *readonlyRootfs) Run() check.Result {
	rt := runtimeAvailable()
	if rt == "" {
		return check.Result{Status: check.Pass, Message: "No container runtime (skipped)"}
	}

	out, err := check.RunCmd(check.DefaultCmdTimeout, rt, "ps", "-q")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return check.Result{Status: check.Pass, Message: "No running containers"}
	}

	ids := strings.Fields(strings.TrimSpace(string(out)))
	var rwRoot []string
	for _, id := range ids {
		inspOut, _ := check.RunCmd(check.DefaultCmdTimeout, rt, "inspect", "--format", "{{.HostConfig.ReadonlyRootfs}}", id)
		if strings.TrimSpace(string(inspOut)) != "true" {
			rwRoot = append(rwRoot, id[:12])
		}
	}

	if len(rwRoot) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     fmt.Sprintf("%d container(s) without read-only root filesystem", len(rwRoot)),
			Remediation: "Use --read-only flag when starting containers",
			Details:     map[string]string{"containers": strings.Join(rwRoot, "\n")},
		}
	}
	return check.Result{Status: check.Pass, Message: "All containers use read-only root filesystem"}
}

// CTR-010
type loggingDriver struct{}

func (c *loggingDriver) ID() string               { return "CTR-010" }
func (c *loggingDriver) Name() string             { return "Docker logging driver configured" }
func (c *loggingDriver) Category() string         { return "container" }
func (c *loggingDriver) Severity() check.Severity { return check.Low }
func (c *loggingDriver) Description() string      { return "Verify Docker logging driver is set" }

func (c *loggingDriver) Run() check.Result {
	if !dockerAvailable() {
		return check.Result{Status: check.Pass, Message: "Docker not installed (skipped)"}
	}

	out, err := check.RunCmd(check.DefaultCmdTimeout, "docker", "info", "--format", "{{.LoggingDriver}}")
	if err != nil {
		return check.Result{Status: check.Warn, Message: "Cannot query Docker logging driver"}
	}

	driver := strings.TrimSpace(string(out))
	if driver == "none" {
		return check.Result{
			Status: check.Warn, Message: "Docker logging driver is 'none'",
			Remediation: "Set logging driver in daemon.json: {\"log-driver\": \"json-file\"}",
		}
	}
	return check.Result{Status: check.Pass, Message: "Docker logging driver: " + driver}
}

// CTR-011
type trustedRegistries struct{}

func (c *trustedRegistries) ID() string               { return "CTR-011" }
func (c *trustedRegistries) Name() string             { return "Images from trusted registries" }
func (c *trustedRegistries) Category() string         { return "container" }
func (c *trustedRegistries) Severity() check.Severity { return check.Medium }
func (c *trustedRegistries) Description() string {
	return "Check if container images come from trusted registries"
}

func (c *trustedRegistries) Run() check.Result {
	rt := runtimeAvailable()
	if rt == "" {
		return check.Result{Status: check.Pass, Message: "No container runtime (skipped)"}
	}

	out, err := check.RunCmd(check.DefaultCmdTimeout, rt, "images", "--format", "{{.Repository}}")
	if err != nil {
		return check.Result{Status: check.Pass, Message: "Cannot list images"}
	}

	trusted := []string{"docker.io", "gcr.io", "ghcr.io", "quay.io", "registry.access.redhat.com"}
	var untrusted []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "<none>" {
			continue
		}
		isTrusted := false
		for _, t := range trusted {
			if strings.HasPrefix(line, t) || !strings.Contains(line, ".") {
				isTrusted = true
				break
			}
		}
		if !isTrusted {
			untrusted = append(untrusted, line)
		}
	}

	if len(untrusted) > 0 {
		return check.Result{
			Status:  check.Warn,
			Message: "Images from untrusted registries: " + strings.Join(untrusted, ", "),
		}
	}
	return check.Result{Status: check.Pass, Message: "All images from trusted registries"}
}
