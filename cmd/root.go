package cmd

import (
	"fmt"
	"os"

	"github.com/civanmoreno/infraudit/internal/version"
	"github.com/spf13/cobra"
)

var showVersion bool

var rootCmd = &cobra.Command{
	Use:   version.Name,
	Short: "Infrastructure auditing toolkit",
	Long: `infraudit - Infrastructure Auditing Toolkit

A modular CLI for auditing infrastructure configurations,
security posture, and compliance across your environments.`,
	Run: func(cmd *cobra.Command, args []string) {
		if showVersion {
			fmt.Printf("%s v%s\n", version.Name, version.Version)
			return
		}
		_ = cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Print version information")
}
