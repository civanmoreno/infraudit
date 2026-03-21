package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available audit checks",
	Long:  `Display a table of all registered checks with their ID, category, severity, and description.`,
	Run:   runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) {
	checks := check.All()
	if len(checks) == 0 {
		fmt.Fprintln(os.Stderr, "No checks registered.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCATEGORY\tSEVERITY\tNAME")
	fmt.Fprintln(w, "──\t────────\t────────\t────")
	for _, c := range checks {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.ID(), c.Category(), c.Severity(), c.Name())
	}
	w.Flush()

	fmt.Printf("\nTotal: %d checks\n", len(checks))
}
