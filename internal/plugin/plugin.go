// Package plugin provides a YAML-based custom check system.
// Users define checks in /etc/infraudit/checks.d/*.yaml without recompiling.
package plugin

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

// DefaultDir is the default directory for custom check definitions.
const DefaultDir = "/etc/infraudit/checks.d"

// Definition represents a single custom check defined in YAML.
type Definition struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Category    string   `yaml:"category"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Remediation string   `yaml:"remediation"`
	OS          []string `yaml:"os,omitempty"`
	Init        string   `yaml:"init,omitempty"`
	PkgManager  string   `yaml:"pkg_manager,omitempty"`
	Rule        Rule     `yaml:"rule"`
}

// Rule defines the check logic.
type Rule struct {
	Type string `yaml:"type"` // file_exists, file_missing, file_contains, file_not_contains, file_perms, command

	// For file-based rules
	Path    string `yaml:"path,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`  // regex for file_contains/file_not_contains
	MaxPerm string `yaml:"max_perm,omitempty"` // octal like "0644" for file_perms

	// For command rules
	Command    string   `yaml:"command,omitempty"`
	Args       []string `yaml:"args,omitempty"`
	Expect     string   `yaml:"expect,omitempty"`      // regex to match in stdout (PASS if matches)
	ExpectFail string   `yaml:"expect_fail,omitempty"` // regex — FAIL if matches in stdout
}

// LoadDir loads all .yaml files from a directory and registers them.
// Returns the number of checks loaded and any errors.
func LoadDir(dir string) (int, []error) {
	resolved := check.P(dir)
	entries, err := os.ReadDir(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // no plugin dir is fine
		}
		return 0, []error{fmt.Errorf("reading plugin dir %s: %w", dir, err)}
	}

	var loaded int
	var errs []error

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(resolved, name)
		defs, err := loadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		for _, def := range defs {
			if err := validate(def); err != nil {
				errs = append(errs, fmt.Errorf("%s: check %s: %w", name, def.ID, err))
				continue
			}
			check.Register(newPluginCheck(def))
			loaded++
		}
	}

	return loaded, errs
}

func loadFile(path string) ([]Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseYAML(data)
}

// parseYAML parses a YAML file containing one or more check definitions.
// Supports both a single definition and a list under "checks:" key.
func parseYAML(data []byte) ([]Definition, error) {
	content := string(data)

	// Check if it starts with "checks:" (list format)
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "checks:") {
		return parseChecksList(trimmed)
	}

	// Single definition
	def, err := parseSingleCheck(trimmed)
	if err != nil {
		return nil, err
	}
	return []Definition{def}, nil
}

func parseSingleCheck(content string) (Definition, error) {
	var def Definition
	scanner := bufio.NewScanner(strings.NewReader(content))
	var inRule bool
	var inArgs bool

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if trimmed == "rule:" {
			inRule = true
			inArgs = false
			continue
		}

		if trimmed == "args:" && inRule {
			inArgs = true
			continue
		}

		if inArgs {
			if strings.HasPrefix(trimmed, "- ") {
				def.Rule.Args = append(def.Rule.Args, strings.TrimPrefix(trimmed, "- "))
				continue
			}
			inArgs = false
		}

		key, value, ok := parseYAMLLine(line, inRule)
		if !ok {
			continue
		}

		if inRule {
			switch key {
			case "type":
				def.Rule.Type = value
			case "path":
				def.Rule.Path = value
			case "pattern":
				def.Rule.Pattern = value
			case "max_perm":
				def.Rule.MaxPerm = value
			case "command":
				def.Rule.Command = value
			case "expect":
				def.Rule.Expect = value
			case "expect_fail":
				def.Rule.ExpectFail = value
			}
		} else {
			switch key {
			case "id":
				def.ID = value
			case "name":
				def.Name = value
			case "category":
				def.Category = value
			case "severity":
				def.Severity = value
			case "description":
				def.Description = value
			case "remediation":
				def.Remediation = value
			case "init":
				def.Init = value
			case "pkg_manager":
				def.PkgManager = value
			case "os":
				def.OS = parseInlineList(value)
			}
		}
	}

	return def, scanner.Err()
}

func parseChecksList(content string) ([]Definition, error) {
	// Split on "- id:" boundaries
	lines := strings.Split(content, "\n")
	var defs []Definition
	var current []string
	inChecks := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "checks:" {
			inChecks = true
			continue
		}
		if !inChecks {
			continue
		}
		if strings.HasPrefix(trimmed, "- id:") {
			if len(current) > 0 {
				def, err := parseSingleCheck(strings.Join(current, "\n"))
				if err != nil {
					return nil, err
				}
				defs = append(defs, def)
			}
			current = []string{"id:" + strings.TrimPrefix(trimmed, "- id:")}
			continue
		}
		if len(current) > 0 {
			// Remove leading 2-space indent from list items
			if len(line) > 2 && line[:2] == "  " {
				line = line[2:]
			}
			current = append(current, line)
		}
	}

	if len(current) > 0 {
		def, err := parseSingleCheck(strings.Join(current, "\n"))
		if err != nil {
			return nil, err
		}
		defs = append(defs, def)
	}

	return defs, nil
}

func parseYAMLLine(line string, inRule bool) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}

	key, value, ok := strings.Cut(trimmed, ":")
	if !ok {
		return "", "", false
	}

	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)

	return key, value, true
}

func parseInlineList(s string) []string {
	s = strings.Trim(s, "[]")
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func validate(def Definition) error {
	if def.ID == "" {
		return fmt.Errorf("missing id")
	}
	if def.Name == "" {
		return fmt.Errorf("missing name")
	}
	if def.Category == "" {
		return fmt.Errorf("missing category")
	}
	if def.Severity == "" {
		return fmt.Errorf("missing severity")
	}
	if check.ParseSeverity(def.Severity) < 0 {
		return fmt.Errorf("invalid severity: %s", def.Severity)
	}
	if def.Rule.Type == "" {
		return fmt.Errorf("missing rule.type")
	}

	switch def.Rule.Type {
	case "file_exists", "file_missing":
		if def.Rule.Path == "" {
			return fmt.Errorf("rule.path required for %s", def.Rule.Type)
		}
	case "file_contains", "file_not_contains":
		if def.Rule.Path == "" {
			return fmt.Errorf("rule.path required for %s", def.Rule.Type)
		}
		if def.Rule.Pattern == "" {
			return fmt.Errorf("rule.pattern required for %s", def.Rule.Type)
		}
		if _, err := regexp.Compile(def.Rule.Pattern); err != nil {
			return fmt.Errorf("invalid rule.pattern: %w", err)
		}
	case "file_perms":
		if def.Rule.Path == "" {
			return fmt.Errorf("rule.path required for file_perms")
		}
		if def.Rule.MaxPerm == "" {
			return fmt.Errorf("rule.max_perm required for file_perms")
		}
	case "command":
		if def.Rule.Command == "" {
			return fmt.Errorf("rule.command required for command type")
		}
		if def.Rule.Expect == "" && def.Rule.ExpectFail == "" {
			return fmt.Errorf("rule.expect or rule.expect_fail required for command type")
		}
	default:
		return fmt.Errorf("unknown rule.type: %s", def.Rule.Type)
	}

	return nil
}

// pluginCheck wraps a Definition to implement check.Check.
type pluginCheck struct {
	def Definition
	sev check.Severity
}

func newPluginCheck(def Definition) *pluginCheck {
	return &pluginCheck{
		def: def,
		sev: check.ParseSeverity(def.Severity),
	}
}

func (c *pluginCheck) ID() string               { return c.def.ID }
func (c *pluginCheck) Name() string             { return c.def.Name }
func (c *pluginCheck) Category() string         { return c.def.Category }
func (c *pluginCheck) Severity() check.Severity { return c.sev }
func (c *pluginCheck) Description() string      { return c.def.Description }

func (c *pluginCheck) SupportedOS() []string {
	return c.def.OS
}

func (c *pluginCheck) RequiredInit() string {
	return c.def.Init
}

func (c *pluginCheck) RequiredPkgManager() string {
	return c.def.PkgManager
}

func (c *pluginCheck) Run() check.Result {
	r := c.def.Rule

	switch r.Type {
	case "file_exists":
		return c.runFileExists(r.Path, true)
	case "file_missing":
		return c.runFileExists(r.Path, false)
	case "file_contains":
		return c.runFileContains(r.Path, r.Pattern, true)
	case "file_not_contains":
		return c.runFileContains(r.Path, r.Pattern, false)
	case "file_perms":
		return c.runFilePerms(r.Path, r.MaxPerm)
	case "command":
		return c.runCommand(r.Command, r.Args, r.Expect, r.ExpectFail)
	default:
		return check.Result{
			Status:  check.Error,
			Message: fmt.Sprintf("unknown rule type: %s", r.Type),
		}
	}
}

func (c *pluginCheck) runFileExists(path string, expectExists bool) check.Result {
	resolved := check.P(path)
	_, err := os.Stat(resolved)
	exists := err == nil

	if exists == expectExists {
		msg := fmt.Sprintf("%s exists", path)
		if !expectExists {
			msg = fmt.Sprintf("%s is absent", path)
		}
		return check.Result{Status: check.Pass, Message: msg}
	}

	msg := fmt.Sprintf("%s not found", path)
	if !expectExists {
		msg = fmt.Sprintf("%s should not exist", path)
	}
	return check.Result{
		Status:      check.Fail,
		Message:     msg,
		Remediation: c.def.Remediation,
	}
}

func (c *pluginCheck) runFileContains(path, pattern string, expectMatch bool) check.Result {
	resolved := check.P(path)
	f, err := os.Open(resolved)
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: fmt.Sprintf("cannot read %s: %s", path, err),
		}
	}
	defer f.Close()

	re := regexp.MustCompile(pattern)
	scanner := bufio.NewScanner(f)
	found := false
	for scanner.Scan() {
		if re.MatchString(scanner.Text()) {
			found = true
			break
		}
	}

	if found == expectMatch {
		msg := fmt.Sprintf("pattern %q found in %s", pattern, path)
		if !expectMatch {
			msg = fmt.Sprintf("pattern %q not found in %s", pattern, path)
		}
		return check.Result{Status: check.Pass, Message: msg}
	}

	msg := fmt.Sprintf("pattern %q not found in %s", pattern, path)
	if !expectMatch {
		msg = fmt.Sprintf("unwanted pattern %q found in %s", pattern, path)
	}
	return check.Result{
		Status:      check.Fail,
		Message:     msg,
		Remediation: c.def.Remediation,
	}
}

func (c *pluginCheck) runFilePerms(path, maxPerm string) check.Result {
	resolved := check.P(path)
	info, err := os.Stat(resolved)
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: fmt.Sprintf("cannot stat %s: %s", path, err),
		}
	}

	max, err := strconv.ParseUint(maxPerm, 8, 32)
	if err != nil {
		return check.Result{
			Status:  check.Error,
			Message: fmt.Sprintf("invalid max_perm %q: %s", maxPerm, err),
		}
	}

	actual := uint64(info.Mode().Perm())
	if actual&^max != 0 {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("%s has permissions %04o (max allowed: %s)", path, actual, maxPerm),
			Remediation: c.def.Remediation,
		}
	}

	return check.Result{
		Status:  check.Pass,
		Message: fmt.Sprintf("%s permissions %04o within limit %s", path, actual, maxPerm),
	}
}

func (c *pluginCheck) runCommand(cmd string, args []string, expect, expectFail string) check.Result {
	out, err := check.RunCmd(check.DefaultCmdTimeout, cmd, args...)
	output := string(out)

	if err != nil && expect != "" {
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("command failed: %s %s: %s", cmd, strings.Join(args, " "), err),
			Remediation: c.def.Remediation,
		}
	}

	if expectFail != "" {
		re := regexp.MustCompile(expectFail)
		if re.MatchString(output) {
			return check.Result{
				Status:      check.Fail,
				Message:     fmt.Sprintf("found unwanted pattern in output of %s", cmd),
				Remediation: c.def.Remediation,
			}
		}
		return check.Result{
			Status:  check.Pass,
			Message: fmt.Sprintf("no unwanted patterns in %s output", cmd),
		}
	}

	if expect != "" {
		re := regexp.MustCompile(expect)
		if re.MatchString(output) {
			return check.Result{
				Status:  check.Pass,
				Message: fmt.Sprintf("expected pattern found in %s output", cmd),
			}
		}
		return check.Result{
			Status:      check.Fail,
			Message:     fmt.Sprintf("expected pattern not found in %s output", cmd),
			Remediation: c.def.Remediation,
		}
	}

	return check.Result{Status: check.Pass, Message: "command executed successfully"}
}
