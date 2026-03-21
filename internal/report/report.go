package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/version"
)

// Entry holds one check result for reporting.
type Entry struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Category    string            `json:"category" yaml:"category"`
	Severity    string            `json:"severity" yaml:"severity"`
	Status      string            `json:"status" yaml:"status"`
	Message     string            `json:"message" yaml:"message"`
	Remediation string            `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Details     map[string]string `json:"details,omitempty" yaml:"details,omitempty"`
}

// Report holds the full audit report.
type Report struct {
	Entries []Entry `json:"checks" yaml:"checks"`
	Summary Summary `json:"summary" yaml:"summary"`
}

// Summary holds aggregate counts.
type Summary struct {
	Total    int `json:"total" yaml:"total"`
	Passed   int `json:"passed" yaml:"passed"`
	Warnings int `json:"warnings" yaml:"warnings"`
	Failures int `json:"failures" yaml:"failures"`
	Errors   int `json:"errors" yaml:"errors"`
}

// NewEntry creates a report entry from a check and its result.
func NewEntry(c check.Check, r check.Result) Entry {
	return Entry{
		ID:          c.ID(),
		Name:        c.Name(),
		Category:    c.Category(),
		Severity:    c.Severity().String(),
		Status:      r.Status.String(),
		Message:     r.Message,
		Remediation: r.Remediation,
		Details:     r.Details,
	}
}

// ANSI
const (
	rst     = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
	gray    = "\033[90m"
	bgRed   = "\033[41m"
	bgGreen = "\033[42m"
	bgYell  = "\033[43m"
	bgMag   = "\033[45m"
)

func statusIcon(s string) string {
	switch s {
	case "PASS":
		return green + "✓" + rst
	case "WARN":
		return yellow + "!" + rst
	case "FAIL":
		return red + "✗" + rst
	case "ERROR":
		return magenta + "?" + rst
	default:
		return " "
	}
}

func statusBadge(s string) string {
	switch s {
	case "PASS":
		return green + bold + " PASS  " + rst
	case "WARN":
		return yellow + bold + " WARN  " + rst
	case "FAIL":
		return red + bold + " FAIL  " + rst
	case "ERROR":
		return magenta + bold + " ERROR " + rst
	default:
		return s
	}
}

func severityBadge(s string) string {
	switch s {
	case "CRITICAL":
		return red + bold + s + rst
	case "HIGH":
		return yellow + s + rst
	case "MEDIUM":
		return cyan + s + rst
	case "LOW":
		return blue + s + rst
	case "INFO":
		return gray + s + rst
	default:
		return s
	}
}

// padRight pads s with spaces to width (ignoring ANSI escape sequences).
func padRight(s string, width int) string {
	visible := visibleLen(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

// visibleLen returns the length of s without ANSI escape codes.
func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
			continue
		}
		n++
	}
	return n
}

// categoryOrder provides a consistent display order for categories.
var categoryOrder = []string{
	"auth", "pam", "network", "services", "filesystem", "logging",
	"packages", "hardening", "boot", "cron", "crypto", "secrets",
	"container", "rlimit", "nfs", "malware", "backup",
}

// categoryLabel returns a human-readable label for a category.
var categoryLabels = map[string]string{
	"auth": "Users & Authentication", "pam": "Password Policies",
	"network": "Network & Firewall", "services": "Services & Processes",
	"filesystem": "Filesystem & Permissions", "logging": "Logging & Auditing",
	"packages": "Packages & Updates", "hardening": "Kernel Hardening",
	"boot": "Boot Security & MAC", "cron": "Scheduled Jobs",
	"crypto": "TLS/SSL & Cryptography", "secrets": "Secrets & Credentials",
	"container": "Container Security", "rlimit": "Resource Limits",
	"nfs": "Network Filesystems", "malware": "Rootkits & Malware",
	"backup": "Backups",
}

func catLabel(cat string) string {
	if l, ok := categoryLabels[cat]; ok {
		return l
	}
	return strings.ToUpper(cat)
}

func catPrefix(cat string) string {
	prefixes := map[string]string{
		"auth": "AUTH", "pam": "PAM", "network": "NET", "services": "SVC",
		"filesystem": "FS", "logging": "LOG", "packages": "PKG",
		"hardening": "HARD", "boot": "BOOT", "cron": "CRON",
		"crypto": "CRYPTO", "secrets": "SEC", "container": "CTR",
		"rlimit": "RLIM", "nfs": "NFS", "malware": "MAL", "backup": "BAK",
	}
	if p, ok := prefixes[cat]; ok {
		return p
	}
	return strings.ToUpper(cat)
}

// WriteConsole writes a well-formatted colored console report.
func WriteConsole(w io.Writer, r *Report) {
	// Header
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s%s infraudit v%s — Security Audit Report%s\n", bold, green, version.Version, rst)
	fmt.Fprintf(w, "  %s%s%s\n", dim, strings.Repeat("─", 52), rst)
	fmt.Fprintln(w)

	// Group entries by category
	grouped := make(map[string][]Entry)
	for _, e := range r.Entries {
		grouped[e.Category] = append(grouped[e.Category], e)
	}

	// Sort categories in display order
	var cats []string
	for _, c := range categoryOrder {
		if _, ok := grouped[c]; ok {
			cats = append(cats, c)
		}
	}
	// Add any categories not in the predefined order
	for cat := range grouped {
		found := false
		for _, c := range cats {
			if c == cat {
				found = true
				break
			}
		}
		if !found {
			cats = append(cats, cat)
		}
	}

	for _, cat := range cats {
		entries := grouped[cat]

		// Category header
		prefix := catPrefix(cat)
		label := catLabel(cat)

		// Count stats for this category
		var cp, cw, cf, ce int
		for _, e := range entries {
			switch e.Status {
			case "PASS":
				cp++
			case "WARN":
				cw++
			case "FAIL":
				cf++
			case "ERROR":
				ce++
			}
		}

		catStats := fmt.Sprintf("%s%d passed%s", green, cp, rst)
		if cw > 0 {
			catStats += fmt.Sprintf("  %s%d warn%s", yellow, cw, rst)
		}
		if cf > 0 {
			catStats += fmt.Sprintf("  %s%d fail%s", red, cf, rst)
		}
		if ce > 0 {
			catStats += fmt.Sprintf("  %s%d err%s", magenta, ce, rst)
		}

		fmt.Fprintf(w, "  %s%s%s %s— %s%s   %s\n",
			bold, cyan, prefix, rst, bold, label, catStats)
		fmt.Fprintf(w, "  %s%s%s\n", dim, strings.Repeat("─", 78), rst)

		// Sort entries: FAIL first, then ERROR, WARN, PASS
		sort.SliceStable(entries, func(i, j int) bool {
			return statusPriority(entries[i].Status) > statusPriority(entries[j].Status)
		})

		// Table rows
		for _, e := range entries {
			icon := statusIcon(e.Status)
			status := statusBadge(e.Status)
			sev := padRight(severityBadge(e.Severity), 8)
			id := padRight(dim+e.ID+rst, 12)

			// Truncate message if too long
			msg := e.Message
			if len(msg) > 70 {
				msg = msg[:67] + "..."
			}

			fmt.Fprintf(w, "  %s %s %s %s %s\n",
				icon, status, id, sev, msg)

			if e.Status != "PASS" && e.Remediation != "" {
				rem := e.Remediation
				if len(rem) > 74 {
					rem = rem[:71] + "..."
				}
				fmt.Fprintf(w, "  %s     ↳ %s%s\n", " ", gray+rem, rst)
			}
		}
		fmt.Fprintln(w)
	}

	// Summary box
	writeSummaryBox(w, r)
}

func statusPriority(s string) int {
	switch s {
	case "FAIL":
		return 4
	case "ERROR":
		return 3
	case "WARN":
		return 2
	case "PASS":
		return 1
	default:
		return 0
	}
}

func writeSummaryBox(w io.Writer, r *Report) {
	s := r.Summary
	total := s.Total
	if total == 0 {
		return
	}

	// Progress bar
	barWidth := 40
	passW := barWidth * s.Passed / total
	warnW := barWidth * s.Warnings / total
	failW := barWidth * s.Failures / total
	errW := barWidth * s.Errors / total
	// Ensure at least 1 char for non-zero counts
	if s.Passed > 0 && passW == 0 {
		passW = 1
	}
	if s.Warnings > 0 && warnW == 0 {
		warnW = 1
	}
	if s.Failures > 0 && failW == 0 {
		failW = 1
	}
	if s.Errors > 0 && errW == 0 {
		errW = 1
	}
	// Adjust to fill bar
	used := passW + warnW + failW + errW
	if used < barWidth && s.Passed > 0 {
		passW += barWidth - used
	} else if used < barWidth {
		warnW += barWidth - used
	}

	bar := green + strings.Repeat("█", passW) +
		yellow + strings.Repeat("█", warnW) +
		red + strings.Repeat("█", failW) +
		magenta + strings.Repeat("█", errW) + rst

	fmt.Fprintf(w, "  %s%s%s\n", dim, strings.Repeat("═", 78), rst)
	fmt.Fprintf(w, "  %sSUMMARY%s\n", bold, rst)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s  %s%d%s/%d checks\n", bar, bold, s.Passed, rst, total)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s✓ %d Passed%s", green, s.Passed, rst)
	fmt.Fprintf(w, "    %s! %d Warnings%s", yellow, s.Warnings, rst)
	fmt.Fprintf(w, "    %s✗ %d Failures%s", red, s.Failures, rst)
	fmt.Fprintf(w, "    %s? %d Errors%s\n", magenta, s.Errors, rst)
	fmt.Fprintf(w, "  %s%s%s\n", dim, strings.Repeat("═", 78), rst)
	fmt.Fprintln(w)
}

// WriteJSON writes the report as JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteYAML writes the report as YAML (minimal, no dependency).
func WriteYAML(w io.Writer, r *Report) error {
	fmt.Fprintln(w, "summary:")
	fmt.Fprintf(w, "  total: %d\n", r.Summary.Total)
	fmt.Fprintf(w, "  passed: %d\n", r.Summary.Passed)
	fmt.Fprintf(w, "  warnings: %d\n", r.Summary.Warnings)
	fmt.Fprintf(w, "  failures: %d\n", r.Summary.Failures)
	fmt.Fprintf(w, "  errors: %d\n", r.Summary.Errors)
	fmt.Fprintln(w, "checks:")
	for _, e := range r.Entries {
		fmt.Fprintf(w, "  - id: %s\n", e.ID)
		fmt.Fprintf(w, "    name: %s\n", yamlEscape(e.Name))
		fmt.Fprintf(w, "    category: %s\n", e.Category)
		fmt.Fprintf(w, "    severity: %s\n", e.Severity)
		fmt.Fprintf(w, "    status: %s\n", e.Status)
		fmt.Fprintf(w, "    message: %s\n", yamlEscape(e.Message))
		if e.Remediation != "" {
			fmt.Fprintf(w, "    remediation: %s\n", yamlEscape(e.Remediation))
		}
		if len(e.Details) > 0 {
			fmt.Fprintln(w, "    details:")
			for k, v := range e.Details {
				fmt.Fprintf(w, "      %s: %s\n", yamlEscape(k), yamlEscape(v))
			}
		}
	}
	return nil
}

func yamlEscape(s string) string {
	if strings.ContainsAny(s, ":#{}[]|>&*!%@`'\",\n") {
		return fmt.Sprintf("%q", s)
	}
	return s
}
