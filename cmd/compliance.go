package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/civanmoreno/infraudit/internal/compliance"
	"github.com/civanmoreno/infraudit/internal/report"
	"github.com/spf13/cobra"
)

var (
	complianceLevel  string
	complianceFormat string
)

var complianceCmd = &cobra.Command{
	Use:   "compliance <report.json>",
	Short: "Generate CIS compliance report from audit results",
	Long: `Generate a CIS Benchmark compliance report from a JSON audit report.
Shows compliance percentage per section and lists gaps.

Examples:
  infraudit audit --format json --output report.json
  infraudit compliance report.json
  infraudit compliance report.json --level 2
  infraudit compliance report.json --format json`,
	Args: cobra.ExactArgs(1),
	Run:  runCompliance,
}

func init() {
	complianceCmd.Flags().StringVar(&complianceLevel, "level", "1", "CIS level: 1 or 2")
	complianceCmd.Flags().StringVar(&complianceFormat, "format", "console", "Output format: console, json")
	rootCmd.AddCommand(complianceCmd)
}

type sectionResult struct {
	Name   string `json:"name"`
	Passed int    `json:"passed"`
	Total  int    `json:"total"`
	Pct    int    `json:"percentage"`
}

type complianceReport struct {
	Level    int             `json:"level"`
	Overall  int             `json:"overall_percentage"`
	Passed   int             `json:"passed"`
	Total    int             `json:"total"`
	Sections []sectionResult `json:"sections"`
	Gaps     []gapEntry      `json:"gaps"`
}

type gapEntry struct {
	CheckID string `json:"check_id"`
	Section string `json:"section"`
	Name    string `json:"name"`
	Status  string `json:"status"`
}

func runCompliance(_ *cobra.Command, args []string) {
	// Parse level
	var level compliance.CISLevel
	switch complianceLevel {
	case "1":
		level = compliance.L1
	case "2":
		level = compliance.L2
	default:
		fmt.Fprintf(os.Stderr, "Invalid level: %s (use 1 or 2)\n", complianceLevel)
		os.Exit(1)
	}

	// Load report
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading report: %v\n", err)
		os.Exit(1)
	}
	var rpt report.Report
	if err := json.Unmarshal(data, &rpt); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing report: %v\n", err)
		os.Exit(1)
	}

	// Build entry map
	entryMap := make(map[string]report.Entry, len(rpt.Entries))
	for _, e := range rpt.Entries {
		entryMap[e.ID] = e
	}

	// Get controls for the requested level
	controls := compliance.ControlsByLevel(level)

	// Calculate per-section compliance
	sectionPass := make(map[string]int)
	sectionTotal := make(map[string]int)
	var gaps []gapEntry
	totalPass := 0

	for _, ctrl := range controls {
		cat := ctrl.Category
		sectionTotal[cat]++

		e, exists := entryMap[ctrl.CheckID]
		if !exists {
			gaps = append(gaps, gapEntry{
				CheckID: ctrl.CheckID, Section: ctrl.Section,
				Name: ctrl.SectionName, Status: "NOT RUN",
			})
			continue
		}

		if e.Status == "PASS" {
			sectionPass[cat]++
			totalPass++
		} else {
			gaps = append(gaps, gapEntry{
				CheckID: ctrl.CheckID, Section: ctrl.Section,
				Name: ctrl.SectionName, Status: e.Status,
			})
		}
	}

	// Build section results in order
	var sections []sectionResult
	for _, cisCat := range compliance.CISCategories {
		catKey := cisCat.Number + ". " + cisCat.Name
		total := sectionTotal[catKey]
		if total == 0 {
			continue
		}
		passed := sectionPass[catKey]
		pct := 0
		if total > 0 {
			pct = passed * 100 / total
		}
		sections = append(sections, sectionResult{
			Name: catKey, Passed: passed, Total: total, Pct: pct,
		})
	}

	overallPct := 0
	if len(controls) > 0 {
		overallPct = totalPass * 100 / len(controls)
	}

	cr := complianceReport{
		Level:    int(level),
		Overall:  overallPct,
		Passed:   totalPass,
		Total:    len(controls),
		Sections: sections,
		Gaps:     gaps,
	}

	switch complianceFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cr)
	default:
		writeComplianceConsole(cr)
	}

	if overallPct < 100 {
		os.Exit(1)
	}
}

func writeComplianceConsole(cr complianceReport) {
	fmt.Printf("\n  %sCIS Benchmark Level %d — Compliance Report%s\n", bold+cyan, cr.Level, rst)
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("─", 55), rst)

	// Overall
	overallColor := scoreColorCompliance(cr.Overall)
	fmt.Printf("  %sOverall:%s %s%d%% compliant%s (%d/%d controls passed)\n\n",
		bold, rst, overallColor, cr.Overall, rst, cr.Passed, cr.Total)

	// Section breakdown
	fmt.Printf("  %-42s %5s %6s %5s\n", bold+"Section"+rst, "Pass", "Total", "%")
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 55), rst)

	for _, s := range cr.Sections {
		color := scoreColorCompliance(s.Pct)
		fmt.Printf("  %-42s %5d %6d %s%4d%%%s\n",
			s.Name, s.Passed, s.Total, color, s.Pct, rst)
	}

	// Gaps
	if len(cr.Gaps) > 0 {
		fmt.Printf("\n  %sGaps (%d)%s\n", bold+red, len(cr.Gaps), rst)
		fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 55), rst)
		for _, g := range cr.Gaps {
			statusColor := red
			if g.Status == "WARN" {
				statusColor = yellow
			}
			if g.Status == "NOT RUN" {
				statusColor = dim
			}
			fmt.Printf("  %s%-7s%s %-10s %s — %s\n",
				statusColor, g.Status, rst, g.CheckID, g.Section, g.Name)
		}
	}

	fmt.Printf("\n  %s%s%s\n\n", dim, strings.Repeat("─", 55), rst)
}

func scoreColorCompliance(pct int) string {
	switch {
	case pct >= 90:
		return green + bold
	case pct >= 80:
		return cyan
	case pct >= 70:
		return yellow
	case pct >= 60:
		return yellow
	default:
		return red + bold
	}
}
