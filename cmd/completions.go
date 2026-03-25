package cmd

import (
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
	"github.com/spf13/cobra"
)

func completeCheckIDFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	upper := strings.ToUpper(toComplete)
	var matches []string
	for _, c := range check.All() {
		id := c.ID()
		if strings.HasPrefix(id, upper) {
			matches = append(matches, id+"\t"+c.Name())
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func completeCategoryFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cats := check.Categories()
	var matches []string
	for _, c := range cats {
		if strings.HasPrefix(c, toComplete) {
			matches = append(matches, c)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func completeProfileFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	profiles := []string{"web-server", "db-server", "container-host", "minimal"}
	var matches []string
	for _, p := range profiles {
		if strings.HasPrefix(p, toComplete) {
			matches = append(matches, p)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func completeFormatFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	formats := []string{"console", "json", "yaml", "html", "markdown"}
	var matches []string
	for _, f := range formats {
		if strings.HasPrefix(f, toComplete) {
			matches = append(matches, f)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func completeSeverityFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	levels := []string{"info", "low", "medium", "high", "critical"}
	var matches []string
	for _, l := range levels {
		if strings.HasPrefix(l, toComplete) {
			matches = append(matches, l)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func completeStatusFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	statuses := []string{"pass", "warn", "fail", "error"}
	var matches []string
	for _, s := range statuses {
		if strings.HasPrefix(s, toComplete) {
			matches = append(matches, s)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}
