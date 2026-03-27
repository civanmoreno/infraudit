package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/report"
	"github.com/spf13/cobra"
)

const defaultBaselinePath = "/etc/infraudit/baseline.json"

var baselinePathFlag string

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage audit baselines for regression detection",
	Long: `Save an audit snapshot as a baseline, then compare future audits against it
to detect regressions and improvements.

  infraudit baseline save           Save current audit as baseline
  infraudit baseline check          Run audit and compare against baseline
  infraudit baseline show           Show baseline info
  infraudit baseline clear          Remove saved baseline`,
}

var baselineSaveCmd = &cobra.Command{
	Use:   "save",
	Short: "Save current audit as baseline",
	Long: `Run a full audit and save the results as a baseline snapshot.
Future runs of 'infraudit baseline check' will compare against this baseline.`,
	Run: runBaselineSave,
}

var baselineCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Run audit and compare against baseline",
	Long: `Run a full audit and compare results against the saved baseline.
Reports regressions, improvements, and unchanged checks.
Exits with code 1 if any regressions are found.`,
	Run: runBaselineCheck,
}

var baselineShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show baseline info",
	Run:   runBaselineShow,
}

var baselineClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove saved baseline",
	Run:   runBaselineClear,
}

func init() {
	rootCmd.AddCommand(baselineCmd)
	baselineCmd.AddCommand(baselineSaveCmd)
	baselineCmd.AddCommand(baselineCheckCmd)
	baselineCmd.AddCommand(baselineShowCmd)
	baselineCmd.AddCommand(baselineClearCmd)

	baselineCmd.PersistentFlags().StringVar(&baselinePathFlag, "file", defaultBaselinePath, "baseline file path")
}

// baselineData wraps a report with metadata.
type baselineData struct {
	Version   string         `json:"version"`
	Timestamp string         `json:"timestamp"`
	Hostname  string         `json:"hostname"`
	Report    *report.Report `json:"report"`
}

func runBaselineSave(cmd *cobra.Command, args []string) {
	// Run a full audit silently and capture the report
	rpt := runSilentAudit()

	hostname, _ := os.Hostname()
	data := baselineData{
		Version:   "1",
		Timestamp: time.Now().Format(time.RFC3339),
		Hostname:  hostname,
		Report:    rpt,
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding baseline: %v\n", err)
		os.Exit(1)
	}

	path := baselinePathFlag
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec
		fmt.Fprintf(os.Stderr, "Error creating directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil { //nolint:gosec
		fmt.Fprintf(os.Stderr, "Error writing baseline: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n  %sBaseline saved%s\n", green+bold, rst)
	fmt.Printf("  File:  %s\n", path)
	fmt.Printf("  Score: %d/100 (%s)\n", rpt.Summary.Score, rpt.Summary.Grade)
	fmt.Printf("  Checks: %d total (%d pass, %d warn, %d fail)\n",
		rpt.Summary.Total, rpt.Summary.Passed, rpt.Summary.Warnings, rpt.Summary.Failures)
	fmt.Printf("  Date:  %s\n\n", data.Timestamp)
}

func runBaselineCheck(cmd *cobra.Command, args []string) {
	// Load baseline
	bl, err := loadBaseline(baselinePathFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading baseline: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'infraudit baseline save' first.\n")
		os.Exit(1)
	}

	// Run current audit
	current := runSilentAudit()

	// Compare — use Entries (serialized as "checks" in JSON) for baseline,
	// and AllEntries for current audit (includes all checks before display filters).
	beforeMap := indexEntries(bl.Report.Entries)
	afterMap := indexEntries(current.AllEntries)

	var regressions, improvements, newChecks, unchanged int

	fmt.Printf("\n  %sinfraudit baseline check%s — Regression Report\n", bold, rst)
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 56), rst)
	fmt.Printf("  Baseline: %s (%s)\n", bl.Timestamp, bl.Hostname)
	fmt.Println()

	// Score delta
	scoreDelta := current.Summary.Score - bl.Report.Summary.Score
	deltaStr := fmt.Sprintf("%+d", scoreDelta)
	deltaColor := dim
	if scoreDelta > 0 {
		deltaColor = green + bold
	} else if scoreDelta < 0 {
		deltaColor = red + bold
	}
	fmt.Printf("  %sHardening Index:%s %d (%s) → %d (%s)  %s%s%s\n\n",
		bold, rst,
		bl.Report.Summary.Score, bl.Report.Summary.Grade,
		current.Summary.Score, current.Summary.Grade,
		deltaColor, deltaStr, rst)

	// Find regressions
	var regLines []string
	var impLines []string

	for id, ae := range afterMap {
		be, existed := beforeMap[id]
		if !existed {
			newChecks++
			continue
		}
		if ae.Status == be.Status {
			unchanged++
			continue
		}
		if statusRank(ae.Status) > statusRank(be.Status) {
			regressions++
			regLines = append(regLines, fmt.Sprintf("  %s↓%s %-12s %-8s %s → %s",
				red, rst, id, ae.Severity, diffStatusColor(be.Status), diffStatusColor(ae.Status)))
		} else {
			improvements++
			impLines = append(impLines, fmt.Sprintf("  %s↑%s %-12s %-8s %s → %s",
				green, rst, id, ae.Severity, diffStatusColor(be.Status), diffStatusColor(ae.Status)))
		}
	}

	if regressions > 0 {
		fmt.Printf("  %s%sRegressions (%d)%s\n", red, bold, regressions, rst)
		fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 78), rst)
		for _, l := range regLines {
			fmt.Println(l)
		}
		fmt.Println()
	}

	if improvements > 0 {
		fmt.Printf("  %s%sImprovements (%d)%s\n", green, bold, improvements, rst)
		fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 78), rst)
		for _, l := range impLines {
			fmt.Println(l)
		}
		fmt.Println()
	}

	// Summary
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("═", 78), rst)
	fmt.Printf("  %sSUMMARY%s  ", bold, rst)
	if improvements > 0 {
		fmt.Printf("%s↑ %d improved%s  ", green, improvements, rst)
	}
	if regressions > 0 {
		fmt.Printf("%s↓ %d regressed%s  ", red, regressions, rst)
	}
	if newChecks > 0 {
		fmt.Printf("%s+ %d new%s  ", cyan, newChecks, rst)
	}
	fmt.Printf("%s· %d unchanged%s\n", dim, unchanged, rst)
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("═", 78), rst)

	if regressions > 0 {
		os.Exit(1)
	}
}

func runBaselineShow(cmd *cobra.Command, args []string) {
	bl, err := loadBaseline(baselinePathFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No baseline found at %s\n", baselinePathFlag)
		fmt.Fprintf(os.Stderr, "Run 'infraudit baseline save' first.\n")
		os.Exit(1)
	}

	s := bl.Report.Summary
	fmt.Printf("\n  %sBaseline Info%s\n", bold, rst)
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 40), rst)
	fmt.Printf("  File:      %s\n", baselinePathFlag)
	fmt.Printf("  Host:      %s\n", bl.Hostname)
	fmt.Printf("  Date:      %s\n", bl.Timestamp)
	fmt.Printf("  Score:     %d/100 (%s)\n", s.Score, s.Grade)
	fmt.Printf("  Checks:    %d total\n", s.Total)
	fmt.Printf("  Passed:    %d\n", s.Passed)
	fmt.Printf("  Warnings:  %d\n", s.Warnings)
	fmt.Printf("  Failures:  %d\n", s.Failures)
	fmt.Printf("  Errors:    %d\n", s.Errors)
	if s.Skipped > 0 {
		fmt.Printf("  Skipped:   %d\n", s.Skipped)
	}
	if s.OSInfo != nil {
		name := s.OSInfo.Name
		if s.OSInfo.Version != "" {
			name += " " + s.OSInfo.Version
		}
		fmt.Printf("  OS:        %s (%s)\n", name, s.OSInfo.Family)
	}
	fmt.Println()
}

func runBaselineClear(cmd *cobra.Command, args []string) {
	if err := os.Remove(baselinePathFlag); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No baseline to remove.")
			return
		}
		fmt.Fprintf(os.Stderr, "Error removing baseline: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Baseline removed: %s\n", baselinePathFlag)
}

func loadBaseline(path string) (*baselineData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bl baselineData
	if err := json.Unmarshal(data, &bl); err != nil {
		return nil, fmt.Errorf("invalid baseline JSON: %w", err)
	}
	return &bl, nil
}

// runSilentAudit runs a full audit and returns the report without printing.
func runSilentAudit() *report.Report {
	// Import all check packages (they auto-register via init())
	checks := getAllChecks()
	rpt := &report.Report{}

	for _, c := range checks {
		r := c.Run()
		entry := report.NewEntry(c, r)
		rpt.AllEntries = append(rpt.AllEntries, entry)
		rpt.Entries = append(rpt.Entries, entry)
		rpt.Summary.Total++
		switch r.Status {
		case check.Pass:
			rpt.Summary.Passed++
		case check.Warn:
			rpt.Summary.Warnings++
		case check.Fail:
			rpt.Summary.Failures++
		case check.Error:
			rpt.Summary.Errors++
		case check.Skipped:
			rpt.Summary.Skipped++
		}
	}

	rpt.Summary.Score = report.ComputeScore(rpt.AllEntries)
	rpt.Summary.Grade = report.ScoreGrade(rpt.Summary.Score)
	return rpt
}

// getAllChecks returns all registered checks, respecting OS compatibility.
func getAllChecks() []check.Check {
	return check.All()
}
