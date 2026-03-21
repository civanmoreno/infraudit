package secrets

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ivan/infraudit/internal/check"
)

func init() {
	check.Register(&envSecrets{})
	check.Register(&historySecrets{})
	check.Register(&worldReadableCreds{})
	check.Register(&credFilePerms{})
}

var secretPatterns = []string{
	"PASSWORD=", "PASSWD=", "SECRET=", "API_KEY=",
	"TOKEN=", "AWS_SECRET", "PRIVATE_KEY=",
	"DB_PASSWORD=", "MYSQL_ROOT_PASSWORD=",
}

// SEC-001
type envSecrets struct{}

func (c *envSecrets) ID() string             { return "SEC-001" }
func (c *envSecrets) Name() string           { return "No secrets in environment variables" }
func (c *envSecrets) Category() string       { return "secrets" }
func (c *envSecrets) Severity() check.Severity { return check.High }
func (c *envSecrets) Description() string    { return "Check for secrets in /etc/environment, /etc/profile.d/, .bashrc" }

func (c *envSecrets) Run() check.Result {
	paths := []string{"/etc/environment"}

	// Add profile.d scripts
	entries, _ := os.ReadDir("/etc/profile.d")
	for _, e := range entries {
		paths = append(paths, "/etc/profile.d/"+e.Name())
	}

	var found []string
	for _, p := range paths {
		if scanForSecrets(p) {
			found = append(found, p)
		}
	}

	if len(found) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "Potential secrets found in: " + strings.Join(found, ", "),
			Remediation: "Move secrets to a secure vault or use restricted file permissions",
		}
	}
	return check.Result{Status: check.Pass, Message: "No secrets detected in environment files"}
}

func scanForSecrets(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToUpper(strings.TrimSpace(scanner.Text()))
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, p := range secretPatterns {
			if strings.Contains(line, p) {
				return true
			}
		}
	}
	return false
}

// SEC-002
type historySecrets struct{}

func (c *historySecrets) ID() string             { return "SEC-002" }
func (c *historySecrets) Name() string           { return "No passwords in shell history" }
func (c *historySecrets) Category() string       { return "secrets" }
func (c *historySecrets) Severity() check.Severity { return check.High }
func (c *historySecrets) Description() string    { return "Check shell history files for password-like commands" }

var historyPatterns = []string{
	"mysql -u", "psql -U", "curl.*password",
	"wget.*password", "sshpass", "echo.*password",
	"passwd ", "htpasswd",
}

func (c *historySecrets) Run() check.Result {
	// Check /root and user home directories
	var flagged []string

	homeDirs := []string{"/root"}
	entries, _ := os.ReadDir("/home")
	for _, e := range entries {
		if e.IsDir() {
			homeDirs = append(homeDirs, "/home/"+e.Name())
		}
	}

	for _, home := range homeDirs {
		for _, hist := range []string{".bash_history", ".zsh_history"} {
			path := filepath.Join(home, hist)
			if scanHistoryFile(path) {
				flagged = append(flagged, path)
			}
		}
	}

	if len(flagged) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "Potential credentials in history: " + strings.Join(flagged, ", "),
			Remediation: "Clear history files and configure HISTCONTROL=ignorespace",
		}
	}
	return check.Result{Status: check.Pass, Message: "No obvious credentials in shell history"}
}

func scanHistoryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		for _, p := range historyPatterns {
			if strings.Contains(line, p) {
				return true
			}
		}
	}
	return false
}

// SEC-003
type worldReadableCreds struct{}

func (c *worldReadableCreds) ID() string             { return "SEC-003" }
func (c *worldReadableCreds) Name() string           { return "No credentials in world-readable files" }
func (c *worldReadableCreds) Category() string       { return "secrets" }
func (c *worldReadableCreds) Severity() check.Severity { return check.Critical }
func (c *worldReadableCreds) Description() string    { return "Check for credential files that are world-readable" }

func (c *worldReadableCreds) Run() check.Result {
	credFiles := []string{
		"/etc/shadow", "/etc/gshadow",
		"/etc/security/opasswd",
	}

	var bad []string
	for _, f := range credFiles {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0004 != 0 {
			bad = append(bad, fmt.Sprintf("%s (%04o)", f, info.Mode().Perm()))
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     "World-readable credential files: " + strings.Join(bad, ", "),
			Remediation: "Fix permissions: chmod 640 for shadow files",
		}
	}
	return check.Result{Status: check.Pass, Message: "Credential files are not world-readable"}
}

// SEC-004
type credFilePerms struct{}

func (c *credFilePerms) ID() string             { return "SEC-004" }
func (c *credFilePerms) Name() string           { return "Credential file permissions correct" }
func (c *credFilePerms) Category() string       { return "secrets" }
func (c *credFilePerms) Severity() check.Severity { return check.High }
func (c *credFilePerms) Description() string    { return "Verify .pgpass, .my.cnf, .netrc are 0600" }

func (c *credFilePerms) Run() check.Result {
	credFiles := []string{".pgpass", ".my.cnf", ".netrc", ".aws/credentials"}
	var bad []string

	homeDirs := []string{"/root"}
	entries, _ := os.ReadDir("/home")
	for _, e := range entries {
		if e.IsDir() {
			homeDirs = append(homeDirs, "/home/"+e.Name())
		}
	}

	for _, home := range homeDirs {
		for _, cf := range credFiles {
			path := filepath.Join(home, cf)
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			perm := info.Mode().Perm()
			if perm > 0600 {
				bad = append(bad, fmt.Sprintf("%s (%04o)", path, perm))
			}
		}
	}

	if len(bad) > 0 {
		return check.Result{
			Status:      check.Warn,
			Message:     "Credential files with loose permissions: " + strings.Join(bad, ", "),
			Remediation: "Fix: chmod 600 on credential files",
		}
	}
	return check.Result{Status: check.Pass, Message: "Credential file permissions are correct"}
}
