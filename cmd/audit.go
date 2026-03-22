package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/config"
	"github.com/civanmoreno/infraudit/internal/report"
	"github.com/spf13/cobra"
)

var (
	categoryFlag string
	formatFlag   string
	outputFlag   string
	profileFlag  string
	skipFlag     []string
	parallelFlag int
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run security audit checks",
	Long: `Execute all registered security checks against the current system.
Use --category to filter by a specific check category.
Use --profile to apply a predefined server profile.
Use --format to change output format (console, json, yaml).`,
	Run: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&categoryFlag, "category", "", "Filter checks by category (e.g. auth, network, services)")
	auditCmd.Flags().StringVar(&formatFlag, "format", "console", "Output format: console, json, yaml")
	auditCmd.Flags().StringVar(&outputFlag, "output", "", "Write report to file")
	auditCmd.Flags().StringVar(&profileFlag, "profile", "", "Server profile: web-server, db-server, container-host, minimal")
	auditCmd.Flags().StringSliceVar(&skipFlag, "skip", nil, "Skip specific check IDs (comma-separated)")
	auditCmd.Flags().IntVar(&parallelFlag, "parallel", 0, "Run checks in parallel with N workers (0=sequential)")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) {
	// Load config
	cfg := config.Load()

	// Apply profile if specified
	if profileFlag != "" {
		profile, ok := config.Profiles[profileFlag]
		if !ok {
			fmt.Fprintf(os.Stderr, "Unknown profile: %s\nAvailable: web-server, db-server, container-host, minimal\n", profileFlag)
			os.Exit(1)
		}
		// Merge profile into config
		cfg.SkipCategories = append(cfg.SkipCategories, profile.SkipCategories...)
		cfg.AllowedPorts = append(cfg.AllowedPorts, profile.AllowedPorts...)
	}

	// Add CLI skip flags
	cfg.Skip = append(cfg.Skip, skipFlag...)

	// Store config globally so checks can access it
	config.Set(cfg)

	// Get checks
	var checks []check.Check
	if categoryFlag != "" {
		checks = check.ByCategory(categoryFlag)
	} else {
		checks = check.All()
	}

	if len(checks) == 0 {
		if categoryFlag != "" {
			fmt.Fprintf(os.Stderr, "No checks found for category: %s\n", categoryFlag)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "No checks registered.")
		os.Exit(1)
	}

	// Filter skipped checks
	var active []check.Check
	for _, c := range checks {
		if !cfg.ShouldSkip(c.ID(), c.Category()) {
			active = append(active, c)
		}
	}
	total := len(active)

	// Run checks and build report
	rpt := &report.Report{}

	if parallelFlag > 0 && total > 1 {
		// Parallel execution with worker pool
		type checkResult struct {
			check  check.Check
			result check.Result
		}

		jobs := make(chan check.Check, total)
		results := make(chan checkResult, total)
		var completed atomic.Int32

		var wg sync.WaitGroup
		for i := 0; i < parallelFlag; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for c := range jobs {
					r := c.Run()
					results <- checkResult{check: c, result: r}
					done := completed.Add(1)
					fmt.Fprintf(os.Stderr, "\r  Running checks... %d/%d", done, total)
				}
			}()
		}

		for _, c := range active {
			jobs <- c
		}
		close(jobs)

		go func() {
			wg.Wait()
			close(results)
		}()

		for cr := range results {
			entry := report.NewEntry(cr.check, cr.result)
			rpt.Entries = append(rpt.Entries, entry)
			rpt.Summary.Total++
			switch cr.result.Status {
			case check.Pass:
				rpt.Summary.Passed++
			case check.Warn:
				rpt.Summary.Warnings++
			case check.Fail:
				rpt.Summary.Failures++
			case check.Error:
				rpt.Summary.Errors++
			}
		}
		fmt.Fprint(os.Stderr, "\r                              \r")
	} else {
		// Sequential execution
		for i, c := range active {
			fmt.Fprintf(os.Stderr, "\r  Running checks... %d/%d", i+1, total)
			r := c.Run()
			entry := report.NewEntry(c, r)
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
			}
		}
		fmt.Fprint(os.Stderr, "\r                              \r")
	}

	// Determine output writer
	var w *os.File
	if outputFlag != "" {
		outputFlag = filepath.Clean(outputFlag)
		f, err := os.Create(outputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create output file: %s\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	} else {
		w = os.Stdout
	}

	// Write report
	switch formatFlag {
	case "json":
		if err := report.WriteJSON(w, rpt); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %s\n", err)
			os.Exit(1)
		}
	case "yaml":
		if err := report.WriteYAML(w, rpt); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing YAML: %s\n", err)
			os.Exit(1)
		}
	default:
		report.WriteConsole(w, rpt)
	}

	if outputFlag != "" {
		fmt.Fprintf(os.Stderr, "Report written to %s\n", outputFlag)
	}

	// Exit code
	if rpt.Summary.Failures > 0 || rpt.Summary.Errors > 0 {
		os.Exit(2)
	}
	if rpt.Summary.Warnings > 0 {
		os.Exit(1)
	}
}
