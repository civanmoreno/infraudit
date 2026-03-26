package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/civanmoreno/infraudit/internal/report"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff <before.json> <after.json>",
	Short: "Compare two audit reports and show changes",
	Long: `Compare two JSON audit reports and show what improved, regressed, or stayed the same.

Use this after remediation to demonstrate progress:
  infraudit audit --format json --output before.json
  # ... apply fixes ...
  infraudit audit --format json --output after.json
  infraudit diff before.json after.json`,
	Args: cobra.ExactArgs(2),
	Run:  runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
}

type diffChange struct {
	ID         string
	Name       string
	Severity   string
	Before     string
	After      string
	ChangeType string // "improved", "regressed", "new", "removed", "unchanged"
}

func runDiff(cmd *cobra.Command, args []string) {
	before, err := loadReport(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", args[0], err)
		os.Exit(1)
	}
	after, err := loadReport(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", args[1], err)
		os.Exit(1)
	}

	// Index entries by ID
	beforeMap := indexEntries(before.Entries)
	afterMap := indexEntries(after.Entries)

	var changes []diffChange

	// Checks in both reports
	for id, ae := range afterMap {
		be, existed := beforeMap[id]
		if !existed {
			changes = append(changes, diffChange{
				ID: id, Name: ae.Name, Severity: ae.Severity,
				Before: "-", After: ae.Status, ChangeType: "new",
			})
			continue
		}
		if be.Status == ae.Status {
			changes = append(changes, diffChange{
				ID: id, Name: ae.Name, Severity: ae.Severity,
				Before: be.Status, After: ae.Status, ChangeType: "unchanged",
			})
		} else if statusRank(ae.Status) < statusRank(be.Status) {
			changes = append(changes, diffChange{
				ID: id, Name: ae.Name, Severity: ae.Severity,
				Before: be.Status, After: ae.Status, ChangeType: "improved",
			})
		} else {
			changes = append(changes, diffChange{
				ID: id, Name: ae.Name, Severity: ae.Severity,
				Before: be.Status, After: ae.Status, ChangeType: "regressed",
			})
		}
	}

	// Checks removed in after
	for id, be := range beforeMap {
		if _, exists := afterMap[id]; !exists {
			changes = append(changes, diffChange{
				ID: id, Name: be.Name, Severity: be.Severity,
				Before: be.Status, After: "-", ChangeType: "removed",
			})
		}
	}

	// Sort: regressed first, then improved, new, removed, unchanged
	sort.SliceStable(changes, func(i, j int) bool {
		return changeTypePriority(changes[i].ChangeType) > changeTypePriority(changes[j].ChangeType)
	})

	// Count changes
	var improved, regressed, newChecks, removed, unchanged int
	for _, c := range changes {
		switch c.ChangeType {
		case "improved":
			improved++
		case "regressed":
			regressed++
		case "new":
			newChecks++
		case "removed":
			removed++
		case "unchanged":
			unchanged++
		}
	}

	// Print header
	fmt.Printf("\n  %sinfraudit diff%s — Audit Comparison\n", bold, rst)
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("─", 52), rst)

	// Score comparison
	scoreDelta := after.Summary.Score - before.Summary.Score
	deltaStr := fmt.Sprintf("%+d", scoreDelta)
	deltaColor := dim
	if scoreDelta > 0 {
		deltaColor = green + bold
	} else if scoreDelta < 0 {
		deltaColor = red + bold
	}
	fmt.Printf("  %sHardening Index:%s %d (%s) → %d (%s)  %s%s%s\n\n",
		bold, rst,
		before.Summary.Score, before.Summary.Grade,
		after.Summary.Score, after.Summary.Grade,
		deltaColor, deltaStr, rst)

	// Print regressions
	if regressed > 0 {
		fmt.Printf("  %s%sRegressions (%d)%s\n", red, bold, regressed, rst)
		fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 78), rst)
		for _, c := range changes {
			if c.ChangeType == "regressed" {
				printDiffLine(c)
			}
		}
		fmt.Println()
	}

	// Print improvements
	if improved > 0 {
		fmt.Printf("  %s%sImprovements (%d)%s\n", green, bold, improved, rst)
		fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 78), rst)
		for _, c := range changes {
			if c.ChangeType == "improved" {
				printDiffLine(c)
			}
		}
		fmt.Println()
	}

	// Print new checks
	if newChecks > 0 {
		fmt.Printf("  %s%sNew checks (%d)%s\n", cyan, bold, newChecks, rst)
		fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 78), rst)
		for _, c := range changes {
			if c.ChangeType == "new" {
				fmt.Printf("  %s+%s %-12s %-8s %s → %s\n",
					cyan, rst, c.ID, c.Severity, dim+"-"+rst, diffStatusColor(c.After))
			}
		}
		fmt.Println()
	}

	// Print removed checks
	if removed > 0 {
		fmt.Printf("  %s%sRemoved checks (%d)%s\n", dim, bold, removed, rst)
		fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 78), rst)
		for _, c := range changes {
			if c.ChangeType == "removed" {
				fmt.Printf("  %s-%s %-12s %-8s %s → %s\n",
					dim, rst, c.ID, c.Severity, diffStatusColor(c.Before), dim+"-"+rst)
			}
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("═", 78), rst)
	fmt.Printf("  %sSUMMARY%s  ", bold, rst)
	if improved > 0 {
		fmt.Printf("%s↑ %d improved%s  ", green, improved, rst)
	}
	if regressed > 0 {
		fmt.Printf("%s↓ %d regressed%s  ", red, regressed, rst)
	}
	if newChecks > 0 {
		fmt.Printf("%s+ %d new%s  ", cyan, newChecks, rst)
	}
	if removed > 0 {
		fmt.Printf("%s- %d removed%s  ", dim, removed, rst)
	}
	fmt.Printf("%s· %d unchanged%s\n", dim, unchanged, rst)
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("═", 78), rst)

	// Exit code: 1 if any regressions
	if regressed > 0 {
		os.Exit(1)
	}
}

func loadReport(path string) (*report.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return &r, nil
}

func indexEntries(entries []report.Entry) map[string]report.Entry {
	m := make(map[string]report.Entry, len(entries))
	for _, e := range entries {
		m[e.ID] = e
	}
	return m
}

// statusRank returns a numeric rank for status (lower = better).
func statusRank(s string) int {
	switch s {
	case "PASS":
		return 0
	case "WARN":
		return 1
	case "FAIL":
		return 2
	case "ERROR":
		return 3
	default:
		return 4
	}
}

func changeTypePriority(t string) int {
	switch t {
	case "regressed":
		return 5
	case "improved":
		return 4
	case "new":
		return 3
	case "removed":
		return 2
	case "unchanged":
		return 1
	default:
		return 0
	}
}

func printDiffLine(c diffChange) {
	arrow := dim + " → " + rst
	icon := green + "↑" + rst
	if c.ChangeType == "regressed" {
		icon = red + "↓" + rst
	}
	fmt.Printf("  %s %-12s %-8s %s%s%s\n",
		icon, c.ID, c.Severity, diffStatusColor(c.Before), arrow, diffStatusColor(c.After))
}

func diffStatusColor(s string) string {
	switch s {
	case "PASS":
		return green + bold + "PASS" + rst
	case "WARN":
		return yellow + bold + "WARN" + rst
	case "FAIL":
		return red + bold + "FAIL" + rst
	case "ERROR":
		return magenta + bold + "ERROR" + rst
	default:
		return dim + s + rst
	}
}
