package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteMarkdown writes the report as Markdown.
func WriteMarkdown(w io.Writer, r *Report) error {
	s := r.Summary

	fmt.Fprintln(w, "# infraudit — Security Audit Report")
	fmt.Fprintln(w)
	summary := fmt.Sprintf("**%d** checks | **%d** passed | **%d** warnings | **%d** failures | **%d** errors",
		s.Total, s.Passed, s.Warnings, s.Failures, s.Errors)
	if s.Skipped > 0 {
		summary += fmt.Sprintf(" | **%d** skipped", s.Skipped)
	}
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Hardening Index: %d/100 (%s)**\n", s.Score, s.Grade)
	if s.Duration > 0 {
		fmt.Fprintf(w, "\nCompleted in %.1fs\n", s.Duration)
	}
	fmt.Fprintln(w)

	// Group by category
	grouped := make(map[string][]Entry)
	for _, e := range r.Entries {
		grouped[e.Category] = append(grouped[e.Category], e)
	}

	for _, cat := range categoryOrder {
		entries, ok := grouped[cat]
		if !ok {
			continue
		}

		// Sort: fail first, then error, warn, pass
		sort.SliceStable(entries, func(i, j int) bool {
			return statusPriority(entries[i].Status) > statusPriority(entries[j].Status)
		})

		label := catLabel(cat)
		prefix := catPrefix(cat)
		fmt.Fprintf(w, "## %s — %s\n\n", prefix, label)
		fmt.Fprintln(w, "| Status | ID | Severity | Finding |")
		fmt.Fprintln(w, "|:-------|:---|:---------|:--------|")

		for _, e := range entries {
			icon := mdStatusIcon(e.Status)
			msg := e.Message
			if e.Remediation != "" {
				msg += " — *" + e.Remediation + "*"
			}
			// Escape pipes in message
			msg = strings.ReplaceAll(msg, "|", "\\|")
			fmt.Fprintf(w, "| %s %s | `%s` | %s | %s |\n",
				icon, e.Status, e.ID, e.Severity, msg)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func mdStatusIcon(s string) string {
	switch s {
	case "PASS":
		return "✅"
	case "WARN":
		return "⚠️"
	case "FAIL":
		return "❌"
	case "ERROR":
		return "❓"
	case "SKIPPED":
		return "⏭️"
	default:
		return ""
	}
}
