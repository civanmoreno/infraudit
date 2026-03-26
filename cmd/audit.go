package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/civanmoreno/infraudit/internal/config"
	"github.com/civanmoreno/infraudit/internal/policy"
	"github.com/civanmoreno/infraudit/internal/report"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	categoryFlag    string
	formatFlag      string
	outputFlag      string
	profileFlag     string
	skipFlag        []string
	parallelFlag    int
	quietFlag       bool
	severityMinFlag string
	checkFlag       string
	statusFlag      string
	ignoreErrors    bool
	policyFlag      string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run security audit checks",
	Long: `Execute all registered security checks against the current system.
Use --category to filter by check categories (comma-separated).
Use --profile to apply a predefined server profile.
Use --format to change output format (console, json, yaml).`,
	Run: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&categoryFlag, "category", "", "Filter by category (comma-separated: auth,network,crypto)")
	auditCmd.Flags().StringVar(&formatFlag, "format", "console", "Output format: console, json, yaml, html, markdown")
	auditCmd.Flags().StringVar(&outputFlag, "output", "", "Write report to file")
	auditCmd.Flags().StringVar(&profileFlag, "profile", "", "Server profile: web-server, db-server, container-host, minimal")
	auditCmd.Flags().StringSliceVar(&skipFlag, "skip", nil, "Skip specific check IDs (comma-separated)")
	auditCmd.Flags().IntVar(&parallelFlag, "parallel", 0, "Run checks in parallel with N workers (0=sequential)")
	auditCmd.Flags().BoolVarP(&quietFlag, "quiet", "q", false, "Suppress progress output")
	auditCmd.Flags().StringVar(&severityMinFlag, "severity-min", "", "Show only results at or above this severity (low,medium,high,critical)")
	auditCmd.Flags().StringVar(&checkFlag, "check", "", "Run a single check by ID (e.g. AUTH-001)")
	auditCmd.Flags().StringVar(&statusFlag, "status", "", "Show only results with these statuses (comma-separated: pass,warn,fail,error)")
	auditCmd.Flags().BoolVar(&ignoreErrors, "ignore-errors", false, "Don't count errors toward exit code 2")
	auditCmd.Flags().StringVar(&policyFlag, "enforce-policy", "", "Enforce a policy file (auto-detects .infraudit-policy.json if empty)")
	_ = auditCmd.RegisterFlagCompletionFunc("check", completeCheckIDFlag)
	_ = auditCmd.RegisterFlagCompletionFunc("category", completeCategoryFlag)
	_ = auditCmd.RegisterFlagCompletionFunc("profile", completeProfileFlag)
	_ = auditCmd.RegisterFlagCompletionFunc("format", completeFormatFlag)
	_ = auditCmd.RegisterFlagCompletionFunc("severity-min", completeSeverityFlag)
	_ = auditCmd.RegisterFlagCompletionFunc("status", completeStatusFlag)
	rootCmd.AddCommand(auditCmd)
}

// showProgress returns true if progress indicator should be displayed.
func showProgress() bool {
	if quietFlag {
		return false
	}
	return term.IsTerminal(int(os.Stderr.Fd()))
}

func progress(done, total int) {
	if showProgress() {
		fmt.Fprintf(os.Stderr, "\033[2K\r  Running checks... %d/%d", done, total)
	}
}

func clearProgress() {
	if showProgress() {
		fmt.Fprint(os.Stderr, "\033[2K\r")
	}
}

func runAudit(cmd *cobra.Command, args []string) {
	start := time.Now()

	// Load config
	cfg := config.Load()

	// Apply profile if specified
	if profileFlag != "" {
		profile, ok := config.Profiles[profileFlag]
		if !ok {
			fmt.Fprintf(os.Stderr, "Unknown profile: %s\nAvailable: web-server, db-server, container-host, minimal\n", profileFlag)
			os.Exit(1)
		}
		cfg.SkipCategories = append(cfg.SkipCategories, profile.SkipCategories...)
		cfg.AllowedPorts = append(cfg.AllowedPorts, profile.AllowedPorts...)
	}

	// Add CLI skip flags
	cfg.Skip = append(cfg.Skip, skipFlag...)

	// Store config globally so checks can access it
	config.Set(cfg)

	// Get checks
	var checks []check.Check
	switch {
	case checkFlag != "":
		c := check.ByID(checkFlag)
		if c == nil {
			fmt.Fprintf(os.Stderr, "Check not found: %s\n", checkFlag)
			os.Exit(1)
		}
		checks = []check.Check{c}
	case categoryFlag != "":
		cats := strings.Split(categoryFlag, ",")
		for i := range cats {
			cats[i] = strings.TrimSpace(cats[i])
		}
		if len(cats) == 1 {
			checks = check.ByCategory(cats[0])
		} else {
			checks = check.ByCategories(cats)
		}
	default:
		checks = check.All()
	}

	if len(checks) == 0 {
		switch {
		case checkFlag != "":
			fmt.Fprintf(os.Stderr, "Check not found: %s\n", checkFlag)
		case categoryFlag != "":
			fmt.Fprintf(os.Stderr, "No checks found for category: %s\n", categoryFlag)
		default:
			fmt.Fprintln(os.Stderr, "No checks registered.")
		}
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

	// Parse severity filter
	var minSeverity check.Severity = -1
	if severityMinFlag != "" {
		minSeverity = check.ParseSeverity(severityMinFlag)
		if minSeverity < 0 {
			fmt.Fprintf(os.Stderr, "Invalid severity: %s\nValid values: info, low, medium, high, critical\n", severityMinFlag)
			os.Exit(1)
		}
	}

	// Parse status filter
	var statusFilter map[string]bool
	if statusFlag != "" {
		statusFilter = make(map[string]bool)
		for _, s := range strings.Split(statusFlag, ",") {
			s = strings.ToUpper(strings.TrimSpace(s))
			if s != "PASS" && s != "WARN" && s != "FAIL" && s != "ERROR" {
				fmt.Fprintf(os.Stderr, "Invalid status: %s\nValid values: pass, warn, fail, error\n", s)
				os.Exit(1)
			}
			statusFilter[s] = true
		}
	}

	// Run checks and build report
	rpt := &report.Report{}

	if parallelFlag > 0 && total > 1 {
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
					done := int(completed.Add(1))
					progress(done, total)
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
			addResult(rpt, cr.check, cr.result, minSeverity, statusFilter)
		}
	} else {
		for i, c := range active {
			progress(i+1, total)
			r := c.Run()
			addResult(rpt, c, r, minSeverity, statusFilter)
		}
	}

	clearProgress()

	// Set duration and hardening score (computed on ALL entries, before display filters)
	rpt.Summary.Duration = time.Since(start).Seconds()
	rpt.Summary.Score = report.ComputeScore(rpt.AllEntries)
	rpt.Summary.Grade = report.ScoreGrade(rpt.Summary.Score)

	// Determine output writer
	var w *os.File
	var outFile *os.File
	if outputFlag != "" {
		outputFlag = filepath.Clean(outputFlag)
		f, err := os.Create(outputFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create output file: %s\n", err)
			os.Exit(1)
		}
		outFile = f
		w = f
	} else {
		w = os.Stdout
	}

	// Write report
	var writeErr error
	switch formatFlag {
	case "json":
		writeErr = report.WriteJSON(w, rpt)
	case "yaml":
		writeErr = report.WriteYAML(w, rpt)
	case "html":
		writeErr = report.WriteHTML(w, rpt)
	case "markdown", "md":
		writeErr = report.WriteMarkdown(w, rpt)
	case "sarif":
		writeErr = report.WriteSARIF(w, rpt)
	default:
		report.WriteConsole(w, rpt)
	}

	// Close output file before any exit
	if outFile != nil {
		if err := outFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing output file: %s\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", outputFlag)
	}

	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "Error writing report: %s\n", writeErr)
		os.Exit(1)
	}

	// Policy enforcement
	if cmd.Flags().Changed("enforce-policy") {
		policyPath := policyFlag
		if policyPath == "" {
			policyPath = policy.FindPolicyFile()
		}
		if policyPath != "" {
			pol, err := policy.Load(policyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading policy: %v\n", err)
				os.Exit(1)
			}
			result := policy.Enforce(pol, rpt)
			if !result.Passed {
				fmt.Fprintf(os.Stderr, "\n  %s%sPOLICY VIOLATION%s (%s)\n", red, bold, rst, policyPath)
				fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, strings.Repeat("─", 50), rst)
				fmt.Fprint(os.Stderr, policy.FormatViolations(result))
				fmt.Fprintf(os.Stderr, "  %s%s%s\n\n", dim, strings.Repeat("─", 50), rst)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "\n  %s✓ Policy passed%s (%s)\n\n", green, rst, policyPath)
		}
	}

	// Exit code
	hasFailures := rpt.Summary.Failures > 0
	hasErrors := !ignoreErrors && rpt.Summary.Errors > 0
	if hasFailures || hasErrors {
		os.Exit(2)
	}
	if rpt.Summary.Warnings > 0 {
		os.Exit(1)
	}
}

func addResult(rpt *report.Report, c check.Check, r check.Result, minSeverity check.Severity, statusFilter map[string]bool) {
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

	entry := report.NewEntry(c, r)
	rpt.AllEntries = append(rpt.AllEntries, entry)

	// Apply severity filter to displayed entries
	if minSeverity >= 0 && c.Severity() < minSeverity {
		return
	}
	// Apply status filter to displayed entries
	if statusFilter != nil && !statusFilter[r.Status.String()] {
		return
	}
	rpt.Entries = append(rpt.Entries, entry)
}
