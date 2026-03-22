package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/spf13/cobra"
)

var catFormatFlag string

var categoriesCmd = &cobra.Command{
	Use:   "categories",
	Short: "List available check categories",
	Long:  `Display all check categories with the number of checks in each.`,
	Run:   runCategories,
}

func init() {
	categoriesCmd.Flags().StringVar(&catFormatFlag, "format", "table", "Output format: table, json")
	rootCmd.AddCommand(categoriesCmd)
}

func runCategories(cmd *cobra.Command, args []string) {
	checks := check.All()

	// Count per category
	counts := make(map[string]int)
	for _, c := range checks {
		counts[c.Category()]++
	}

	// Sort by category order
	cats := make([]string, 0, len(counts))
	for cat := range counts {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool {
		return categoryOrder[cats[i]] < categoryOrder[cats[j]]
	})

	if catFormatFlag == "json" {
		type catEntry struct {
			Category string `json:"category"`
			Checks   int    `json:"checks"`
		}
		entries := make([]catEntry, len(cats))
		for i, cat := range cats {
			entries[i] = catEntry{Category: cat, Checks: counts[cat]}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(entries)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CATEGORY\tCHECKS")
	fmt.Fprintln(w, "────────\t──────")
	total := 0
	for _, cat := range cats {
		fmt.Fprintf(w, "%s\t%d\n", cat, counts[cat])
		total += counts[cat]
	}
	_ = w.Flush()
	fmt.Printf("\n%d categories, %d checks total\n", len(cats), total)
}
