package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/spf13/cobra"
)

var (
	listCategoryFlag string
	listSeverityFlag string
	listFormatFlag   string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available audit checks",
	Long:  `Display a table of all registered checks with their ID, category, severity, and description.`,
	Run:   runList,
}

func init() {
	listCmd.Flags().StringVar(&listCategoryFlag, "category", "", "Filter by category (comma-separated)")
	listCmd.Flags().StringVar(&listSeverityFlag, "severity", "", "Filter by minimum severity (info,low,medium,high,critical)")
	listCmd.Flags().StringVar(&listFormatFlag, "format", "table", "Output format: table, json")
	rootCmd.AddCommand(listCmd)
}

// categoryOrder defines the display order for categories.
var categoryOrder = map[string]int{
	"auth": 0, "pam": 1, "network": 2, "services": 3,
	"filesystem": 4, "logging": 5, "packages": 6, "hardening": 7,
	"boot": 8, "cron": 9, "crypto": 10, "secrets": 11,
	"container": 12, "rlimit": 13, "nfs": 14, "malware": 15, "backup": 16,
}

func runList(cmd *cobra.Command, args []string) {
	checks := check.All()
	if len(checks) == 0 {
		fmt.Fprintln(os.Stderr, "No checks registered.")
		return
	}

	// Filter by category
	if listCategoryFlag != "" {
		cats := make(map[string]bool)
		for _, c := range strings.Split(listCategoryFlag, ",") {
			cats[strings.TrimSpace(c)] = true
		}
		var filtered []check.Check
		for _, c := range checks {
			if cats[c.Category()] {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}

	// Filter by severity
	if listSeverityFlag != "" {
		minSev := check.ParseSeverity(listSeverityFlag)
		if minSev < 0 {
			fmt.Fprintf(os.Stderr, "Invalid severity: %s\nValid values: info, low, medium, high, critical\n", listSeverityFlag)
			os.Exit(1)
		}
		var filtered []check.Check
		for _, c := range checks {
			if c.Severity() >= minSev {
				filtered = append(filtered, c)
			}
		}
		checks = filtered
	}

	// Sort by category order, then by ID
	sort.Slice(checks, func(i, j int) bool {
		ci, cj := categoryOrder[checks[i].Category()], categoryOrder[checks[j].Category()]
		if ci != cj {
			return ci < cj
		}
		return checks[i].ID() < checks[j].ID()
	})

	if len(checks) == 0 {
		fmt.Fprintln(os.Stderr, "No checks match the given filters.")
		return
	}

	if listFormatFlag == "json" {
		writeListJSON(checks)
		return
	}

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCATEGORY\tSEVERITY\tNAME")
	fmt.Fprintln(w, "──\t────────\t────────\t────")
	for _, c := range checks {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.ID(), c.Category(), c.Severity(), c.Name())
	}
	_ = w.Flush()

	fmt.Printf("\nTotal: %d checks\n", len(checks))
}

type listEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

func writeListJSON(checks []check.Check) {
	entries := make([]listEntry, len(checks))
	for i, c := range checks {
		entries[i] = listEntry{
			ID:       c.ID(),
			Name:     c.Name(),
			Category: c.Category(),
			Severity: c.Severity().String(),
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(entries)
}
