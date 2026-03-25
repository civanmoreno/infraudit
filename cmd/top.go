package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/config"
	"github.com/civanmoreno/infraudit/internal/report"
	"github.com/spf13/cobra"
)

var topCount int

var topCmd = &cobra.Command{
	Use:   "top",
	Short: "Show the most critical findings",
	Long:  `Run all checks and display only the top N most critical findings, sorted by severity.`,
	Run:   runTop,
}

func init() {
	topCmd.Flags().IntVarP(&topCount, "count", "n", 10, "Number of findings to show")
	rootCmd.AddCommand(topCmd)
}

func runTop(cmd *cobra.Command, args []string) {
	start := time.Now()
	config.Set(config.Load())

	checks := check.All()
	var entries []report.Entry
	var summary report.Summary

	for _, c := range checks {
		r := c.Run()
		summary.Total++
		switch r.Status {
		case check.Pass:
			summary.Passed++
		case check.Warn:
			summary.Warnings++
		case check.Fail:
			summary.Failures++
		case check.Error:
			summary.Errors++
		}
		if r.Status != check.Pass {
			entries = append(entries, report.NewEntry(c, r))
		}
	}

	// Sort by severity (critical first), then by status (fail > error > warn)
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	statusOrder := map[string]int{"FAIL": 0, "ERROR": 1, "WARN": 2}
	sort.SliceStable(entries, func(i, j int) bool {
		si, sj := sevOrder[entries[i].Severity], sevOrder[entries[j].Severity]
		if si != sj {
			return si < sj
		}
		return statusOrder[entries[i].Status] < statusOrder[entries[j].Status]
	})

	if len(entries) > topCount {
		entries = entries[:topCount]
	}

	summary.Duration = time.Since(start).Seconds()

	// Display
	fmt.Printf("\n  %s%sTop %d Findings%s\n", bold, red, len(entries), rst)
	fmt.Printf("  %s%s%s\n\n", dim, strings.Repeat("─", 60), rst)

	for i, e := range entries {
		sClr := statusColor(e.Status)
		sevClr := severityColor(check.ParseSeverity(e.Severity))
		fmt.Printf("  %s%d.%s %s%s%s  %s%s%s  %s%s%s\n",
			dim, i+1, rst,
			sClr, e.Status, rst,
			sevClr, e.Severity, rst,
			dim, e.ID, rst)
		fmt.Printf("     %s\n", e.Message)
		if e.Remediation != "" {
			fmt.Printf("     %s↳ %s%s\n", dim, e.Remediation, rst)
		}
		fmt.Println()
	}

	// Mini summary
	fmt.Printf("  %s%s%s\n", dim, strings.Repeat("─", 60), rst)
	fmt.Printf("  %d/%d checks  ", summary.Total-summary.Passed, summary.Total)
	fmt.Printf("%s%d fail%s  %s%d warn%s  %s%d err%s",
		red, summary.Failures, rst,
		yellow, summary.Warnings, rst,
		magenta, summary.Errors, rst)
	fmt.Printf("  %sCompleted in %.1fs%s\n\n", dim, summary.Duration, rst)

	if summary.Failures > 0 || summary.Errors > 0 {
		os.Exit(2)
	}
	if summary.Warnings > 0 {
		os.Exit(1)
	}
}
